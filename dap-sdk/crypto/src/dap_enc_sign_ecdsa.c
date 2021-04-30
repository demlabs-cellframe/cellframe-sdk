#include "dap_enc_sign_ecdsa.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

typedef struct ecdsa_pvt_serialize{
    dap_enc_curve_types_t curve_type:32;
    uint64_t size_key;
    byte_t data[];
}DAP_ALIGN_PACKED ecdsa_pvt_serialize_t;

void dap_enc_sign_ecdsa_key_new(struct dap_enc_key *a_key){
    //a_key->type = DAP_ENC_KEY_TYPE_ECDSA_0;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_ecdsa_get;
    a_key->dec_na = dap_enc_sign_ecdsa_verify;
    //1a_key->
}
//void _dap_enc_sign_ecdsa_key
void dap_enc_sign_ecdsa_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                         const void *seed, size_t seed_size, size_t key_size) {
    (void)kex_size;
    (void)seed;
    (void)seed_size;
    a_key->pub_key_data = DAP_NEW(dap_enc_key_public_ecdsa_t);
    a_key->pub_key_data_size = sizeof (dap_enc_key_public_ecdsa_t);
    a_key->priv_key_data = DAP_NEW(dap_enc_key_private_ecdsa_t);
    a_key->priv_key_data_size = sizeof(dap_enc_key_private_ecdsa_t);
    const ecdsa_curve *curve = NULL;
    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_ECDSA_ED25519:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_NIST256P1:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        curve = &nist256p1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_SECP256K1:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561k1;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561k1;
        curve = &secp256k1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ED25519_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ED25519_Blake2b:
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519Blake2b;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519Blake2b;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_CURVE25519:
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_CURVE25519;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_CURVE25519;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_NIST256P1_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        curve = &nist256p1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_SECP256K1_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561k1;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561k1;
        curve = &secp256k1;
        break;
    default:
        log_it(L_ERROR, "Key have type ");
        return;
    }
    random_buffer(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                  ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key);
    bool gen_public_key = false;
    if (curve != NULL){
        //GET public key size
        if (key_size == 33){
            ecdsa_get_public_key33(curve, ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                                   ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data);
            gen_public_key = true;
        }
        if (key_size == 65){
            ecdsa_get_public_key65(curve, ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                                   ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data);
            gen_public_key = true;
        }
    } else {
        if(((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type == DAP_ENC_CURVE_TYPE_ED25519){
            if (key_size == 32){
                ed25519_publickey(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                                  ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data);
                gen_public_key = true;
            }
            if (key_size == 64){
                //TODO
//                    ed25519_publickey_ext()
            }
        } else if (((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type == DAP_ENC_CURVE_TYPE_ED25519Blake2b){
            ed25519_publickey_blake2b(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                                      ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data);
            gen_public_key = true;
        } else if (((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type == DAP_ENC_CURVE_TYPE_CURVE25519){
            uint8_t *tmp_key;
            ed25519_publickey(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                              ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data);
            ed25519_pk_to_curve25519(((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->data, tmp_key);
            DAP_FREE(tmp_key);
            gen_public_key = true;
        }
    }
    if(!gen_public_key){
        log_it(L_ERROR, "Can't generated key");
        DAP_FREE(a_key->pub_key_data);
        a_key->pub_key_data_size = 0;
        DAP_FREE(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data);
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = 0;
        DAP_FREE(a_key->priv_key_data);
        a_key->priv_key_data_size = 0;
        return;
    }
}
size_t dap_enc_sign_ecdsa_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){    
    if(signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    /*ecdsa_curve *curve;
    return (size_t)ecdsa_sign(curve, HASHER_SHA3, a_key->priv_key_data, msg, (uint32_t)msg_size, signature, NULL, NULL);*/
}
size_t dap_enc_sign_ecdsa_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                 void *signature, const size_t signature_size){
    if (signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    ecdsa_curve *curve;
    return ecdsa_verify(curve, HASHER_SHA3, a_key->pub_key_data, signature, msg, (uint32_t)msg_size) == 0?1:0;
}

size_t dap_enc_sign_ecdsa_calc_signature_size(void){
    return sizeof(uint64_t);
}
size_t dap_enc_sign_ecdsa_calc_signature_serialized_size(void){
    return sizeof(uint64_t);
}

/* Serialize a signature */
uint8_t* dap_enc_sign_ecdsa_write_signature(uint8_t *a_sign, size_t *a_sign_out){
    if (!a_sign || *a_sign_out != dap_enc_sign_ecdsa_calc_signature_size()){
        return NULL;
    }
    size_t l_shift_mem = 0;
    size_t l_buff_len = dap_enc_sign_ecdsa_calc_signature_serialized_size();
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, l_buff_len);
    memcpy(l_out, a_sign, sizeof(uint64_t));
    l_shift_mem += sizeof(uint64_t);

    if (a_sign_out)
        *a_sign_out = l_buff_len;
    return l_out;
}

/* Deserialize a signature */
uint8_t* dap_enc_sign_ecdsa_read_signature(uint8_t *a_buff, size_t a_buff_size){
    if(!a_buff || a_buff_size != dap_enc_sign_ecdsa_calc_signature_serialized_size()){
        return NULL;
    }
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, sizeof(uint64_t));
    memcpy(l_out, a_buff, sizeof(uint64_t));
    return l_out;
}

/* Serialize a private key */
uint8_t *dap_enc_sign_ecdsa_write_private_key(const dap_enc_key_private_ecdsa_t *a_private_key, size_t *a_buflen_out){
    if (a_private_key == NULL) {
        return NULL;
    }
    if (a_private_key->size_key == 0){
        return NULL;
    }
    ecdsa_pvt_serialize_t *pvt = DAP_NEW_Z_SIZE(ecdsa_pvt_serialize_t, sizeof(*pvt) + a_private_key->size_key);
    pvt->curve_type = a_private_key->curve_type;
    pvt->size_key = a_private_key->size_key;
    memcpy(pvt->data, a_private_key->data, sizeof(byte_t) * a_private_key->size_key);
    if (a_buflen_out)
        *a_buflen_out = sizeof(*pvt) + a_private_key->size_key;
    return (uint8_t*)pvt;
}

/* Serialize a public key */
uint8_t *dap_enc_sign_ecdsa_write_public_key(const dap_enc_key_public_ecdsa_t *a_public_key, size_t *a_buflen_out){
    size_t l_buff_len = sizeof (size_t) + sizeof (size_t) + (sizeof (size_t) * a_public_key->size_key);
    size_t l_shift_bytes = 0;
    size_t type_curve = a_public_key->curve_type;
    uint8_t *l_buff_out = DAP_NEW_SIZE(uint8_t, l_buff_len);
    memcpy(l_buff_out, &type_curve, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, &a_public_key->size_key, sizeof(size_t));
    l_shift_bytes += sizeof(size_t);
    memcpy(l_buff_out + l_shift_bytes, a_public_key->data, sizeof(uint8_t) * a_public_key->size_key);
    if (a_buflen_out)
        *a_buflen_out = l_buff_len;
    return l_buff_out;
}

/* Deserialize a private key. */
dap_enc_key_private_ecdsa_t *dap_enc_sign_ecdsa_read_private_key(const uint8_t *a_buf, size_t a_buflen){
    if (!a_buf || a_buflen < sizeof (size_t) + sizeof(size_t)){
        return  NULL;
    }
    dap_enc_key_private_ecdsa_t *l_private_key = DAP_NEW(dap_enc_key_private_ecdsa_t);
    size_t l_shift_bytes = 0;
    size_t type_curve;
    memcpy(&type_curve, a_buf, sizeof (size_t));
    l_shift_bytes += sizeof (size_t);
    l_private_key->curve_type = (dap_enc_curve_types_t)type_curve;
    memcpy(&l_private_key->size_key, a_buf + l_shift_bytes, sizeof (size_t));
    l_shift_bytes += sizeof (size_t);
    if ((l_shift_bytes + sizeof (uint8_t) * l_private_key->size_key) != a_buflen){
        DAP_FREE(l_private_key);
        return NULL;
    }
    l_private_key->data = DAP_NEW_SIZE(uint8_t, sizeof(uint8_t) * l_private_key->size_key);
    memcpy(l_private_key->data, a_buf + l_shift_bytes, sizeof(uint8_t) * l_private_key->size_key);
    return l_private_key;
}

/* Deserialize a public key. */
dap_enc_key_public_ecdsa_t *dap_enc_sign_ecdsa_read_public_key(const uint8_t *a_buf, size_t a_buflen){
    if(!a_buf || a_buflen < sizeof(size_t) + sizeof (size_t)){
        return  NULL;
    }
    dap_enc_key_public_ecdsa_t *l_public_key = DAP_NEW(dap_enc_key_public_ecdsa_t);
    size_t l_shift_bytes = 0;
    size_t l_type_curve;
    memcpy(&l_type_curve, a_buf, sizeof(size_t));
    l_shift_bytes += sizeof (size_t);
    memcpy(&l_public_key->size_key, a_buf + l_shift_bytes, sizeof(size_t));
    l_shift_bytes += sizeof (size_t);
    if ((l_shift_bytes + sizeof (uint8_t) * l_public_key->size_key) != a_buflen){
        DAP_FREE(l_public_key);
        return NULL;
    }
    l_public_key->curve_type = (dap_enc_curve_types_t)l_type_curve;
    memcpy(l_public_key->data, a_buf + l_shift_bytes, sizeof(uint8_t) * l_public_key->size_key);
    return l_public_key;
}
