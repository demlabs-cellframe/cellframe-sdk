#include "dap_enc_sign_schnorr.h"

#define LOG_TAG "dap_enc_sign_schnorr"

void dap_enc_sign_schnorr_key_new(struct dap_enc_key * a_key){
    a_key->type = DAP_ENC_KEY_TYPE_SCHNORR_0;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_schnorr_get;
    a_key->dec_na = dap_enc_sign_schnorr_verify;
}

void dap_enc_sign_schnorr_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                            const void *seed, size_t seed_size, size_t key_size){
    if (a_key == NULL)
        return;
    (void)kex_buf;
    (void)kex_size;
    (void)seed;
    (void)seed_size;
    (void)key_size;
    a_key->priv_key_data = DAP_NEW(dap_enc_key_sign_schnorr_private_t);
    a_key->priv_key_data_size = sizeof (dap_enc_key_sign_schnorr_private_t);
    a_key->pub_key_data = DAP_NEW(dap_enc_key_sign_schnorr_public_t);
    a_key->pub_key_data_size = sizeof(dap_enc_key_sign_schnorr_public_t);
    const ecdsa_curve *curve = &secp256k1;
    ((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
    random_buffer(((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->data,
                  ((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->size_key);
    ((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_public_secp256k1_size;
    ecdsa_get_public_key33(curve, ((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->data,
                           ((dap_enc_key_sign_schnorr_public_t*)a_key)->data);
}
size_t dap_enc_sign_schnorr_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    if(signature_size < sizeof(schnorr_sign_pair)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    int i;
    bignum256 k;
    uint8_t hash[32];
    sha256_Raw(msg, msg_size, hash);
    rfc6979_state rfc_state;
    init_rfc6979(((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->data, hash, &rfc_state);

    if (((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->curve_type == DAP_ENC_CYRVE_TYPE_SECP256k1){
        for (i = 0; i < 10000; i++) {
            const ecdsa_curve *curve = &secp256k1;
            generate_k_rfc6979(&k, &rfc_state);
            if (bn_is_zero(&k) || !bn_is_less(&k, &curve->order)){
                continue;
            }
            schnorr_sign_pair *sign = DAP_NEW(schnorr_sign_pair);
            int result = schnorr_sign(curve,
                             ((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->data,
                             &k, msg,(uint32_t) msg_size, sign);
            if (result == 0 ){
                memset(&k, 0, sizeof (k));
                memset(&rfc_state, 0, sizeof (rfc_state));
                signature = sign;
                return sizeof(schnorr_sign_pair);
            } else {
                DAP_FREE(sign);
                continue;
            }
        }
        memset(&k, 0, sizeof (k));
        memset(&rfc_state, 0, sizeof (rfc_state));
    }
    return 0;
}
size_t dap_enc_sign_schnorr_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    if(signature_size < sizeof(schnorr_sign_pair)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    const ecdsa_curve *curve = &secp256k1;
    return (size_t)schnorr_verify(curve,
                                  ((dap_enc_key_sign_schnorr_public_t*)a_key->pub_key_data)->data,
                                  msg, (uint32_t)msg_size, (schnorr_sign_pair*)signature);
}

void dap_enc_sign_schnorr_key_delete(struct dap_enc_key *a_key){
    DAP_FREE(((dap_enc_key_sign_schnorr_private_t*)a_key->priv_key_data)->data);
    DAP_FREE(((dap_enc_key_sign_schnorr_private_t*)a_key->pub_key_data)->data);
    DAP_FREE(a_key->priv_key_data);
    a_key->priv_key_data_size = 0;
    DAP_FREE(a_key->pub_key_data);
    a_key->pub_key_data_size = 0;
}

size_t dap_enc_sign_schnorr_calc_signature_size(void){
    return sizeof(schnorr_sign_pair);
}
size_t dap_enc_sign_schnorr_calc_signature_serialized_size(void){
    return ((sizeof (uint8_t) * 32) +(sizeof (uint8_t) * 32));
}

/* Serialize a signature */
uint8_t* dap_enc_sign_schnorr_write_signature(schnorr_sign_pair *a_sign, size_t *a_sign_out){
    if(!a_sign || *a_sign_out!=sizeof(schnorr_sign_pair)) {
        return NULL ;
    }
    size_t l_shift_mem = 0;
    size_t l_buff_len = dap_enc_sign_schnorr_calc_signature_serialized_size();
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, l_buff_len);
    memcpy(l_out, a_sign->r, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    memcpy(l_out + l_shift_mem, a_sign->s, sizeof (uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;

    if (a_sign_out)
        *a_sign_out = l_buff_len;
    return l_out;
}

/* Deserialize a signature */
schnorr_sign_pair* dap_enc_sign_schnorr_read_signature(uint8_t *a_buff, size_t a_buff_size){
    if (a_buff_size != dap_enc_sign_schnorr_calc_signature_serialized_size()){
        return NULL;
    }
    schnorr_sign_pair *l_sign = DAP_NEW(schnorr_sign_pair);
    size_t l_shift_mem = 0;
    memcpy(&l_sign->r, a_buff, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    memcpy(&l_sign->s, a_buff + l_shift_mem, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    return  l_sign;
}

/* Serialize a private key */
uint8_t *dap_enc_sign_schnorr_write_private_key(const dap_enc_key_sign_schnorr_private_t *a_private_key, size_t *a_buflen_out){
    if (a_private_key == NULL){
        return NULL;
    }
    size_t l_buff_out_size = sizeof(size_t) + sizeof(size_t) + (sizeof(uint8_t) * a_private_key->size_key);
    uint8_t *l_buff_out = DAP_NEW_SIZE(uint8_t, l_buff_out_size);
    size_t l_shift_bytes = 0;
    size_t l_type_curve = a_private_key->curve_type;
    memcpy(l_buff_out, &l_type_curve, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, &a_private_key->size_key, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, a_private_key->data, sizeof (uint8_t) * a_private_key->size_key);

    if (a_buflen_out)
        *a_buflen_out = l_buff_out_size;
    return  l_buff_out;
}

/* Serialize a public key */
uint8_t *dap_enc_sign_schnorr_write_public_key(const dap_enc_key_sign_schnorr_public_t *a_private_key, size_t *a_buflen_out){
    if (a_private_key == NULL){
        return NULL;
    }
    size_t l_buff_out_size = sizeof(size_t) + sizeof(size_t) + (sizeof(uint8_t) * a_private_key->size_key);
    uint8_t *l_buff_out = DAP_NEW_SIZE(uint8_t, l_buff_out_size);
    size_t l_shift_bytes = 0;
    size_t l_type_curve = a_private_key->curve_type;
    memcpy(l_buff_out, &l_type_curve, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, &a_private_key->size_key, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, &a_private_key->data, sizeof(size_t) * a_private_key->size_key);

    if (a_buflen_out)
        *a_buflen_out = l_buff_out_size;
    return  l_buff_out;
}

/* Deserialize a private key. */
dap_enc_key_sign_schnorr_private_t *dap_enc_sign_schnoor_read_private_key(const uint8_t *a_buf, size_t a_buflen){
    if(!a_buf && a_buflen < sizeof(size_t) + sizeof(size_t) ){
        return NULL;
    }
    dap_enc_key_sign_schnorr_private_t *l_private_key = DAP_NEW(dap_enc_key_sign_schnorr_private_t);
    size_t l_copy_bytes = 0;
    memcpy(&l_private_key->curve_type, a_buf, sizeof(size_t));
    l_copy_bytes += sizeof (size_t);
    memcpy(&l_private_key->size_key, a_buf + l_copy_bytes, sizeof(size_t));
    l_copy_bytes += sizeof (size_t);
    if ((l_copy_bytes + (sizeof (uint8_t) * l_private_key->size_key)) != a_buflen){
        DAP_FREE(l_private_key);
        return NULL;
    }
    l_private_key->data = DAP_NEW_SIZE(uint8_t, l_private_key->size_key);
    memcpy(l_private_key->data, a_buf + l_copy_bytes, sizeof(uint8_t) * l_private_key->size_key);
    return l_private_key;
}

/* Deserialize a public key. */
dap_enc_key_sign_schnorr_public_t *dap_enc_sign_schnoor_read_public_key(const uint8_t *a_buf, size_t a_buflen){
    if (!a_buf || a_buflen < sizeof (size_t) + sizeof(size_t)){
        return NULL;
    }
    dap_enc_key_sign_schnorr_public_t *l_public_key = DAP_NEW(dap_enc_key_sign_schnorr_public_t);
    size_t l_copy_bytes = 0;
    memcpy(&l_public_key->curve_type, a_buf, sizeof (size_t));
    l_copy_bytes += sizeof(size_t);
    memcpy(&l_public_key->size_key, a_buf + l_copy_bytes, sizeof (size_t));
    l_copy_bytes += sizeof(size_t);
    if ((l_copy_bytes + (sizeof (uint8_t) * l_public_key->size_key)) != a_buflen){
        DAP_FREE(l_public_key);
        return NULL;
    }
    l_public_key->data = DAP_NEW_SIZE(uint8_t, l_public_key->size_key);
    memcpy(l_public_key->data, a_buf + l_copy_bytes, sizeof (uint8_t) * l_public_key->size_key);
    return l_public_key;
}
