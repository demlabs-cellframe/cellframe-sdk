
#include "dilithium_params.h"
#include "dap_enc_falcon.h"
#include "falcon.h"

#define LOG_TAG "dap_enc_sig_falcon"

static falcon_sign_degree_t s_falcon_sign_degree = FALCON_512;
static falcon_kind_t s_falcon_kind = FALCON_COMPRESSED;
static falcon_sign_type_t s_falcon_type = FALCON_DYNAMIC;


void dap_enc_sig_falcon_set_degree(falcon_sign_degree_t a_falcon_sign_degree)
{
    if (a_falcon_sign_degree != FALCON_512 && a_falcon_sign_degree != FALCON_1024) {
        log_it(L_ERROR, "Wrong falcon degree");
        return;
    }
    s_falcon_sign_degree = a_falcon_sign_degree;
}

void dap_enc_sig_falcon_set_kind(falcon_kind_t a_falcon_kind)
{
    if (a_falcon_kind != FALCON_COMPRESSED && a_falcon_kind != FALCON_PADDED && a_falcon_kind != FALCON_CT) {
        log_it(L_ERROR, "Wrong falcon kind");
        return;
    }
    s_falcon_kind = a_falcon_kind;
}

void dap_enc_sig_falcon_set_type(falcon_sign_type_t a_falcon_type)
{
    if (a_falcon_type != FALCON_DYNAMIC && a_falcon_type != FALCON_TREE) {
        log_it(L_ERROR, "Wrong falcon type");
        return;
    }
    s_falcon_type = a_falcon_type;
}


void dap_enc_sig_falcon_key_new(struct dap_enc_key *key) {
    key->type = DAP_ENC_KEY_TYPE_SIG_FALCON;
    key->enc = NULL;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_falcon_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_falcon_verify_sign;
}

void dap_enc_sig_falcon_key_new_generate(struct dap_enc_key *key, const void *kex_buf, size_t kex_size,
        const void* seed, size_t seed_size, size_t key_size) {

    key->type = DAP_ENC_KEY_TYPE_SIG_FALCON;
    key->enc = NULL;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_falcon_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_falcon_verify_sign;


    int retcode = 0;
    unsigned int logn = s_falcon_sign_degree;
    size_t tmp[FALCON_TMPSIZE_KEYGEN(logn)];

    key->pub_key_data_size = sizeof(falcon_public_key_t);
    key->priv_key_data_size = sizeof(falcon_private_key_t);
    key->pub_key_data = malloc(key->pub_key_data_size);
    key->priv_key_data = malloc(key->priv_key_data_size);


    uint8_t* privkey = calloc(1, FALCON_PRIVKEY_SIZE(logn));
    uint8_t* pubkey = calloc(1, FALCON_PUBKEY_SIZE(logn));

    falcon_private_key_t privateKey = {s_falcon_kind, s_falcon_sign_degree, s_falcon_type, privkey};
    falcon_public_key_t publicKey = {s_falcon_kind, s_falcon_sign_degree, s_falcon_type, pubkey};

    dap_shake256_context rng;
    retcode = dap_shake256_init_prng_from_system(&rng);
    if (retcode != 0) {
        log_it(L_ERROR, "Failed to initialize PRNG");
        return;
    }
    retcode = dap_falcon_keygen_make(
            &rng,
            logn,
            privateKey.data, FALCON_PRIVKEY_SIZE(logn),
            publicKey.data, FALCON_PUBKEY_SIZE(logn),
//            key->priv_key_data, key->priv_key_data_size,
//            key->pub_key_data, key->pub_key_data_size,
            tmp, FALCON_TMPSIZE_KEYGEN(logn)
            );
    if (retcode != 0) {
        falcon_private_and_public_keys_delete(&privateKey, &publicKey);
        log_it(L_ERROR, "Failed to generate falcon key");
        return;
    }

    memcpy(key->priv_key_data, &privateKey, sizeof(falcon_private_key_t));
    memcpy(key->pub_key_data, &publicKey, sizeof(falcon_public_key_t));

}

size_t dap_enc_falcon_calc_signature_unserialized_size(dap_enc_key_t *key)
{
    falcon_private_key_t *privateKey = key->priv_key_data;
    switch (privateKey->kind) {
    case FALCON_COMPRESSED:
        return FALCON_SIG_COMPRESSED_MAXSIZE(privateKey->degree) + sizeof(falcon_signature_t);
    case FALCON_PADDED:
        return FALCON_SIG_PADDED_SIZE(privateKey->degree) + sizeof(falcon_signature_t);
    case FALCON_CT:
        return FALCON_SIG_CT_SIZE(privateKey->degree) + sizeof(falcon_signature_t);
    default:
        break;
    }
    return 0;
}

size_t dap_enc_sig_falcon_get_sign(struct dap_enc_key* key, const void* msg, const size_t msg_size, void* signature, const size_t signature_size) {
    //todo: do we need to use shared shake256 context?

    int retcode;
    dap_shake256_context rng;
    retcode = dap_shake256_init_prng_from_system(&rng);
    if (retcode != 0) {
        log_it(L_ERROR, "Failed to initialize PRNG");
        return retcode;
    }

    if (key->priv_key_data_size != sizeof(falcon_private_key_t)) {
        log_it(L_ERROR, "Invalid falcon key");
        return -11;
    }
    falcon_private_key_t *privateKey = key->priv_key_data;

    size_t tmpsize = privateKey->type == FALCON_DYNAMIC ?
                FALCON_TMPSIZE_SIGNDYN(privateKey->degree) :
                FALCON_TMPSIZE_SIGNTREE(privateKey->degree);
    uint8_t tmp[tmpsize];

    falcon_signature_t *sig = signature;
    sig->degree = privateKey->degree;
    sig->kind = privateKey->kind;
    sig->type = privateKey->type;
    size_t sig_len = signature_size - sizeof(falcon_signature_t);
    sig->sig_data = DAP_NEW_SIZE(byte_t, sig_len);
    retcode = dap_falcon_sign_dyn(
            &rng,
            sig->sig_data, &sig_len, privateKey->kind,
            privateKey->data, FALCON_PRIVKEY_SIZE(privateKey->degree),
            msg, msg_size,
            tmp, tmpsize
            );
    sig->sig_len = sig_len;
    if (retcode != 0)
        log_it(L_ERROR, "Failed to sign message");
    return retcode;
}

size_t dap_enc_sig_falcon_verify_sign(struct dap_enc_key* key, const void* msg, const size_t msg_size, void* signature,
                                      const size_t signature_size)
{
    if (key->pub_key_data_size != sizeof(falcon_private_key_t)) {
        log_it(L_ERROR, "Invalid falcon key");
        return -11;
    }
    falcon_private_key_t *publicKey = key->pub_key_data;
    int logn = publicKey->degree;

    uint8_t tmp[FALCON_TMPSIZE_VERIFY(logn)];
    falcon_signature_t *sig = signature;
    if (sig->degree != publicKey->degree ||
            sig->kind != publicKey->kind ||
            sig->type != publicKey->type)
        return -1;
    int retcode = dap_falcon_verify(
            sig->sig_data, sig->sig_len, publicKey->kind,
            publicKey->data, FALCON_PUBKEY_SIZE(publicKey->degree),
            msg, msg_size,
            tmp, FALCON_TMPSIZE_VERIFY(logn)
            );
    if (retcode != 0)
        log_it(L_ERROR, "Failed to verify signature");
    return retcode;
}

void dap_enc_sig_falcon_key_delete(struct dap_enc_key *key) {

    if (key->priv_key_data) {
        memset(key->priv_key_data, 0, key->priv_key_data_size);
        DAP_DEL_Z(key->priv_key_data);
    }
    if (key->pub_key_data) {
        memset(key->pub_key_data, 0, key->pub_key_data_size);
        DAP_DEL_Z(key->pub_key_data);
    }
}

// Serialize a public key into a buffer.
uint8_t* dap_enc_falcon_write_public_key(const falcon_public_key_t* a_public_key, size_t* a_buflen_out) {
    //Serialized key have format:
    // 8 first bytes - size of overall serialized key
    // 4 bytes - degree of key
    // 4 bytes - kind of key
    // 4 bytes - type of key
    // n bytes - public key data

    uint64_t l_buflen =
            sizeof(uint64_t) +
            sizeof(uint32_t) * 3 +
            FALCON_PUBKEY_SIZE(a_public_key->degree);

    uint8_t *l_buf = DAP_NEW_Z_SIZE(uint8_t, l_buflen);
    uint32_t l_degree = a_public_key->degree;
    uint32_t l_kind = a_public_key->kind;
    uint32_t l_type = a_public_key->type;

    uint8_t *l_ptr = l_buf;
    *(uint64_t *)l_ptr = l_buflen; l_ptr += sizeof(uint64_t);
    *(uint32_t *)l_ptr = l_degree; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_kind; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_type; l_ptr += sizeof(uint32_t);
    memcpy(l_ptr, a_public_key->data, FALCON_PUBKEY_SIZE(a_public_key->degree));
    assert(l_ptr + FALCON_PUBKEY_SIZE(a_public_key->degree) - l_buf == (int64_t)l_buflen);

    if (a_buflen_out)
        *a_buflen_out = l_buflen;

    return l_buf;
}

uint8_t* dap_enc_falcon_write_private_key(const falcon_private_key_t* a_private_key, size_t* a_buflen_out) {
    //Serialized key have format:
    // 8 first bytes - size of overall serialized key
    // 4 bytes - degree of key
    // 4 bytes - kind of key
    // 4 bytes - type of key
    // n bytes - private key data

    uint64_t l_buflen =
            sizeof(uint64_t) +
            sizeof(uint32_t) * 3 +
            FALCON_PRIVKEY_SIZE(a_private_key->degree);

    uint8_t *l_buf = DAP_NEW_Z_SIZE(uint8_t, l_buflen);
    uint32_t l_degree = a_private_key->degree;
    uint32_t l_kind = a_private_key->kind;
    uint32_t l_type = a_private_key->type;
    uint8_t *l_ptr = l_buf;
    *(uint64_t *)l_ptr = l_buflen; l_ptr += sizeof(uint64_t);
    *(uint32_t *)l_ptr = l_degree; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_kind; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_type; l_ptr += sizeof(uint32_t);
    memcpy(l_ptr, a_private_key->data, FALCON_PRIVKEY_SIZE(a_private_key->degree));
    assert(l_ptr + FALCON_PRIVKEY_SIZE(a_private_key->degree) - l_buf == (int64_t)l_buflen);

    if(a_buflen_out)
        *a_buflen_out = l_buflen;

    return l_buf;
}

falcon_private_key_t* dap_enc_falcon_read_private_key(const uint8_t *a_buf, size_t a_buflen) {
    if (!a_buf) {
        log_it(L_ERROR, "::read_private_key() a_buf is NULL");
        return NULL;
    }

    if (a_buflen < sizeof(uint32_t) * 3) {
        log_it(L_ERROR, "::read_private_key() a_buflen %"DAP_UINT64_FORMAT_U" is smaller than first four fields(%zu)", a_buflen, sizeof(uint32_t) * 3);
        return NULL;
    }

    uint64_t l_buflen = 0;
    uint32_t l_degree = 0;
    uint32_t l_kind = 0;
    uint32_t l_type = 0;
    uint8_t *l_ptr = (uint8_t *)a_buf;

    l_buflen = *(uint64_t *)l_ptr; l_ptr += sizeof(uint64_t);
    if (a_buflen < l_buflen) {
        log_it(L_ERROR, "::read_private_key() a_buflen %"DAP_UINT64_FORMAT_U" is less than l_buflen %"DAP_UINT64_FORMAT_U, a_buflen, l_buflen);
        return NULL;
    }

    l_degree = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_degree != FALCON_512 && l_degree != FALCON_1024) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_private_key() degree %ul is not supported", l_degree);
        return NULL;
    }
    if (l_buflen != (sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PRIVKEY_SIZE(l_degree))) {
        log_it(L_ERROR, "::read_private_key() buflen %"DAP_UINT64_FORMAT_U" is not equal to expected size %zu",
               a_buflen, sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PRIVKEY_SIZE(l_degree));
        return NULL;
    }

    l_kind = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_kind != FALCON_COMPRESSED && l_kind != FALCON_PADDED && l_kind != FALCON_CT) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_private_key() kind %ul is not supported", l_kind);
        return NULL;
    }

    l_type = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_type != FALCON_DYNAMIC && l_type != FALCON_TREE) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_private_key() type %ul is not supported", l_type);
        return NULL;
    }

    falcon_private_key_t* l_private_key = DAP_NEW_Z(falcon_private_key_t);
    l_private_key->degree = l_degree;
    l_private_key->kind = l_kind;
    l_private_key->type = l_type;
    l_private_key->data = DAP_NEW_Z_SIZE(uint8_t, FALCON_PRIVKEY_SIZE(l_degree));
    memcpy(l_private_key->data, l_ptr, FALCON_PRIVKEY_SIZE(l_degree));
    assert(l_ptr + FALCON_PRIVKEY_SIZE(l_degree) - a_buf == (int64_t)l_buflen);

    return l_private_key;
}

falcon_public_key_t* dap_enc_falcon_read_public_key(const uint8_t* a_buf, size_t a_buflen) {
    if (!a_buf) {
        log_it(L_ERROR, "::read_public_key() a_buf is NULL");
        return NULL;
    }

    if (a_buflen < sizeof(uint32_t) * 3) {
        log_it(L_ERROR, "::read_public_key() a_buflen %"DAP_UINT64_FORMAT_U" is smaller than first four fields(%zu)", a_buflen, sizeof(uint32_t) * 3);
        return NULL;
    }

    uint64_t l_buflen = 0;
    uint32_t l_degree = 0;
    uint32_t l_kind = 0;
    uint32_t l_type = 0;
    uint8_t *l_ptr = (uint8_t *)a_buf;

    l_buflen = *(uint64_t *)l_ptr; l_ptr += sizeof(uint64_t);
    if (a_buflen < l_buflen) {
        log_it(L_ERROR, "::read_public_key() a_buflen %"DAP_UINT64_FORMAT_U" is less than l_buflen %"DAP_UINT64_FORMAT_U, a_buflen, l_buflen);
        return NULL;
    }

    l_degree = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_degree != FALCON_512 && l_degree != FALCON_1024) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_public_key() l_degree %ul is not supported", l_degree);
        return NULL;
    }
    if (l_buflen != (sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PUBKEY_SIZE(l_degree))) {
        log_it(L_ERROR, "::read_public_key() a_buflen %"DAP_UINT64_FORMAT_U" is not equal to expected size %zu",
                        a_buflen, (sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PUBKEY_SIZE(l_degree)));
        return NULL;
    }

    l_kind = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_kind != FALCON_COMPRESSED && l_kind != FALCON_PADDED && l_kind != FALCON_CT) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_public_key() l_kind %ul is not supported", l_kind);
        return NULL;
    }

    l_type = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_type != FALCON_DYNAMIC && l_type != FALCON_TREE) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_public_key() l_type %ul is not supported", l_type);
        return NULL;
    }

    falcon_public_key_t* l_public_key = DAP_NEW_Z(falcon_public_key_t);
    l_public_key->degree = l_degree;
    l_public_key->kind = l_kind;
    l_public_key->type = l_type;
    l_public_key->data = DAP_NEW_Z_SIZE(uint8_t, FALCON_PUBKEY_SIZE(l_degree));
    memcpy(l_public_key->data, l_ptr, FALCON_PUBKEY_SIZE(l_degree));
    assert(l_ptr + FALCON_PUBKEY_SIZE(l_degree) - a_buf == (int64_t)l_buflen);

    return l_public_key;
}

uint8_t* dap_enc_falcon_write_signature(const falcon_signature_t* a_sign, size_t *a_sign_out) {

    if (!a_sign) {
        log_it(L_ERROR, "::write_signature() a_sign is NULL");
        return NULL;
    }

    size_t l_buflen = sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + a_sign->sig_len;
    uint8_t *l_buf = DAP_NEW_Z_SIZE(uint8_t, l_buflen);
    if (!l_buf) {
        log_it(L_ERROR, "::write_signature() l_buf is NULL — memory allocation error");
        return NULL;
    }

    uint32_t l_degree = a_sign->degree;
    uint32_t l_kind = a_sign->kind;
    uint32_t l_type = a_sign->type;
    uint64_t l_sig_len = a_sign->sig_len;
    uint8_t *l_ptr = l_buf;
    *(uint64_t *)l_ptr = l_buflen; l_ptr += sizeof(uint64_t);
    *(uint32_t *)l_ptr = l_degree; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_kind; l_ptr += sizeof(uint32_t);
    *(uint32_t *)l_ptr = l_type; l_ptr += sizeof(uint32_t);
    *(uint64_t *)l_ptr = l_sig_len; l_ptr += sizeof(uint64_t);
    memcpy(l_ptr, a_sign->sig_data, a_sign->sig_len);
    assert(l_ptr + l_sig_len - l_buf == (int64_t)l_buflen);

    if (a_sign_out)
        *a_sign_out = l_buflen;

    return l_buf;

}
falcon_signature_t* dap_enc_falcon_read_signature(const uint8_t* a_buf, size_t a_buflen) {
    if (!a_buf) {
        log_it(L_ERROR, "::read_signature() a_buf is NULL");
        return NULL;
    }

    if (a_buflen != sizeof(falcon_signature_t)) {
        log_it(L_ERROR, "::read_signature() a_buflen %"DAP_UINT64_FORMAT_U" is not equal to sign struct size (%zu)",
                        a_buflen, sizeof(falcon_signature_t));
        return NULL;
    }

    uint64_t l_buflen = 0;
    uint32_t l_degree = 0;
    uint32_t l_kind = 0;
    uint32_t l_type = 0;
    uint64_t l_sig_len = 0;
    uint8_t *l_ptr = (uint8_t *)a_buf;

    l_buflen = *(uint64_t *)l_ptr; l_ptr += sizeof(uint64_t);

    l_degree = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_degree != FALCON_512 && l_degree != FALCON_1024) { // we are now supporting only 512 and 1024 degrees
        log_it(L_ERROR, "::read_signature() l_degree %ul is not supported", l_degree);
        return NULL;
    }

    l_kind = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_kind != FALCON_COMPRESSED && l_kind != FALCON_PADDED && l_kind != FALCON_CT) { // we are now supporting only compressed, padded and ct signatures
        log_it(L_ERROR, "::read_signature() l_kind %ul is not supported", l_kind);
        return NULL;
    }

    l_type = *(uint32_t *)l_ptr; l_ptr += sizeof(uint32_t);
    if (l_type != FALCON_DYNAMIC && l_type != FALCON_TREE) { // we are now supporting only sign and sign open signatures
        log_it(L_ERROR, "::read_signature() l_type %ul is not supported", l_type);
        return NULL;
    }

    l_sig_len = *(uint64_t *)l_ptr; l_ptr += sizeof(uint64_t);
    if (l_buflen != sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + l_sig_len) {
        log_it(L_ERROR, "::read_signature() l_buflen %"DAP_UINT64_FORMAT_U" is not equal to expected size %zu",
               l_buflen, sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + l_sig_len);
        return NULL;
    }

    falcon_signature_t *l_sign = DAP_NEW(falcon_signature_t);

    l_sign->degree = l_degree;
    l_sign->kind = l_kind;
    l_sign->type = l_type;
    l_sign->sig_len = l_sig_len;
    l_sign->sig_data = DAP_NEW_SIZE(uint8_t, l_sig_len);
    memcpy(l_sign->sig_data, l_ptr, l_sig_len);
    assert(l_ptr + l_sig_len - a_buf == (int64_t)l_buflen);

    return l_sign;
}


void falcon_private_and_public_keys_delete(falcon_private_key_t* privateKey, falcon_public_key_t* publicKey) {
    falcon_private_key_delete(privateKey);
    falcon_public_key_delete(publicKey);
}

void falcon_private_key_delete(falcon_private_key_t* privateKey) {
    if (privateKey) {
        memset(privateKey->data, 0, FALCON_PRIVKEY_SIZE(privateKey->degree));
        DAP_DEL_Z(privateKey->data);
        privateKey->degree = 0;
        privateKey->type = 0;
        privateKey->kind = 0;
    }
}

void falcon_public_key_delete(falcon_public_key_t* publicKey) {
    if (publicKey) {
        memset(publicKey->data, 0, FALCON_PUBKEY_SIZE(publicKey->degree));
        DAP_DEL_Z(publicKey->data);
        publicKey->degree = 0;
        publicKey->type = 0;
        publicKey->kind = 0;
    }
}

