#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "dap_enc_ringct20.h"
#include "dap_common.h"
#include "dap_rand.h"



#define LOG_TAG "dap_enc_sig_ringct20"

DAP_RINGCT20_SIGN_SECURITY _ringct20_type = RINGCT20_MINSEC; // by default
//poly_ringct20 Afixed[10];
//poly_ringct20 Hfixed[10];
#include "ringct20/common.h"

void SetupPrintAH(poly_ringct20 *A, poly_ringct20 * H, const int mLen)
{
    LRCT_Setup(A, H, mLen);
    uint8_t polyb_tmp[NEWHOPE_POLYBYTES];
    printf("A_bpoly[%d][NEWHOPE_POLYBYTES] = {\n", mLen);
    for(int i = 0; i < mLen; ++i)
    {
        poly_tobytes(polyb_tmp,A + i);
        printf("{");
        for(int j = 0; j < NEWHOPE_POLYBYTES; ++j)
        {
            printf("0x%.2x", polyb_tmp[j]);
            if(j < NEWHOPE_POLYBYTES - 1)
                printf(", ");
        }
        printf("}");
        if(i < mLen - 1)
            printf(",\n");
    }
    printf("};\n");
    printf("H_bpoly[%d][NEWHOPE_POLYBYTES] = {\n", mLen);
    for(int i = 0; i < mLen; ++i)
    {
        poly_tobytes(polyb_tmp,H + i);
        printf("{");
        for(int j = 0; j < NEWHOPE_POLYBYTES; ++j)
        {
            printf("0x%.2x", polyb_tmp[j]);
            if(j < NEWHOPE_POLYBYTES - 1)
                printf(", ");
        }
        printf("}");
        if(i < mLen - 1)
            printf(",\n");
    }
    printf("};\n");

}

void ringct20_pack_prk(uint8_t *prk, const poly_ringct20 *S, const ringct20_param_t *rct_p)
{
    for(int i = 0; i < rct_p->M - 1; ++i)
        poly_tobytes(prk + i*rct_p->POLY_RINGCT20_SIZE_PACKED, S +i);

}
void ringct20_unpack_prk(const uint8_t *prk, poly_ringct20 *S, const ringct20_param_t *rct_p)
{
    for(int i = 0; i < rct_p->M - 1; ++i)
        poly_frombytes(S +i, prk + i*rct_p->POLY_RINGCT20_SIZE_PACKED);

}

void ringct20_pack_pbk(uint8_t *pbk, const poly_ringct20 *a, const ringct20_param_t *rct_p)
{
    uint32_t packed_size = 0;
    //pack a
    poly_tobytes(pbk + packed_size, a);
    packed_size += rct_p->POLY_RINGCT20_SIZE_PACKED;

}
void ringct20_unpack_pbk(const uint8_t *pbk, poly_ringct20 *a, const ringct20_param_t *rct_p)
{
    uint32_t unpacked_size = 0;
    //unpack a
    poly_frombytes(a, pbk + unpacked_size);
    unpacked_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
}

void ringct20_unpack_sig(const uint8_t *sig, poly_ringct20 *a_list,
                         poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, const ringct20_param_t *rct_p)
{
    uint32_t unpacked_size = 0;
    //unpack a_list
    for(int i = 0; i < rct_p->wLen; ++i)
    {
        poly_frombytes(a_list + i, sig + unpacked_size);
        unpacked_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
    }
    //unpack t[W][M]
    for(int j = 0; j < rct_p->wLen; ++j)
    {
        for(int i = 0; i < rct_p->M; ++i)
        {
            poly_frombytes(t[j] + i, sig + unpacked_size);
            unpacked_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
        }
    }
    //unpack h
    poly_frombytes(h, sig + unpacked_size);
    unpacked_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
    //unpack c1
    poly_frombytes(c1, sig + unpacked_size);
    unpacked_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
}

void ringct20_pack_sig(uint8_t *sig, const poly_ringct20 *a_list,
                         const poly_ringct20 *c1, const poly_ringct20 **t, const poly_ringct20 *h, const ringct20_param_t *rct_p)
{
    uint32_t packed_size = 0;
    //pack a_list
    for(int i = 0; i < rct_p->wLen; ++i)
    {
        poly_tobytes(sig + packed_size, a_list + i);
        packed_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
    }
    //pack t[W][M]
    for(int j = 0; j < rct_p->wLen; ++j)
    {
        for(int i = 0; i < rct_p->M; ++i)
        {
            poly_tobytes(sig + packed_size,t[j] + i);
            packed_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
        }
    }
    //pack h
    poly_tobytes(sig + packed_size, h);
    packed_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
    //pack c1
    poly_tobytes(sig + packed_size, c1);
    packed_size += rct_p->POLY_RINGCT20_SIZE_PACKED;
}

#define CRUTCH

int get_pbk_list(poly_ringct20 *aList, const ringct20_param_t *p, const int Pi)
{

#ifndef CRUTCH
    return -1;//Здесь должно быть обращение за списком публичных ключей
    ringct20_public_key_t *pbk_list;
   // pbk_list = malloc()
#else
    //get a list of some pbk
    {
        poly_ringct20 *Stmp = malloc(p->POLY_RINGCT20_SIZE*p->mLen);
        for(int i = 0; i < p->wLen; ++i)
        {
            if(i == Pi)
                continue;
            LRCT_SampleKey(Stmp, p->mLen);
            LRCT_KeyGen(aList + i, p->A, Stmp, p->mLen);
        }
        free(Stmp);
    }
#endif
return 0;

}

int ringct20_crypto_sign( ringct20_signature_t *sig, const unsigned char *m, unsigned long long mlen, const ringct20_private_key_t *private_key)
{
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if (! ringct20_params_init( p, private_key->kind)){
        ringct20_params_free(p);
        return -1;
    }

    uint32_t Pi;
    randombytes(&Pi, sizeof(Pi));
    Pi %= p->wLen;
    poly_ringct20 *aList = malloc(p->POLY_RINGCT20_SIZE*p->wLen);
    poly_ringct20 *S =  malloc(p->POLY_RINGCT20_SIZE*p->mLen);
    ringct20_unpack_prk(private_key->data,S,p);

    LRCT_KeyGen(aList + Pi, p->A,S,p->mLen);

    get_pbk_list(aList, p, Pi);


    poly_ringct20 h;
    poly_ringct20 *u = malloc(p->POLY_RINGCT20_SIZE*p->M);
    poly_ringct20 c1;
    poly_ringct20** t;//[w][M]//TOCORRECT to *t;
    t  = malloc(p->wLen*sizeof(poly_ringct20*));
    for(int i = 0; i < p->wLen; ++i)
        t[i] = malloc(p->M*p->POLY_RINGCT20_SIZE);

    unsigned char *bt = malloc(NEWHOPE_POLYBYTES);

    for (int i = 0; i < p->wLen; i++)
    {
        for (int k = 0; k < p->M; k++)
        {
            poly_init(t[i] + k);
        }

    }

    for (int k = 0; k < p->M; k++)
    {
        randombytes(bt, NEWHOPE_POLYBYTES);
        poly_frombytes(u + k, bt);
        poly_serial(u + k);
        //poly_print(u+k);
    }

    free(bt);
    LRCT_SigGen(&c1, t, &h, p->A, p->H, S, u, p->mLen, aList, p->wLen, Pi, m, mlen);
    sig->sig_len = p->RINGCT20_SIG_SIZE;// + mlen;
    sig->sig_data = malloc(sig->sig_len);
//    memcpy(sig->sig_data,m,mlen);//TOCORRECT
    ringct20_pack_sig(sig->sig_data,aList,&c1, t, &h, p);


    free(aList);
    free(S);
    free(u);

    for(int i = 0; i < p->wLen; ++i)
        free(t[i]);
    free(t);

    ringct20_params_free(p);
    return 0;
}
void ringct20_signature_delete(ringct20_signature_t *sig){
    assert(sig != NULL);

    free(sig->sig_data);
    sig->sig_data = NULL;
}
int ringct20_crypto_sign_open( const unsigned char * msg, const unsigned long long msg_size, const ringct20_signature_t * sig, const ringct20_public_key_t* public_key)
{
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if (! ringct20_params_init( p, public_key->kind)){
        ringct20_params_free(p);
        return -1;
    }
    if(sig->sig_len < p->RINGCT20_SIG_SIZE)
    {
        return -1;
    }

    poly_ringct20 *aList = malloc(p->POLY_RINGCT20_SIZE*p->wLen);

    poly_ringct20 h;
    poly_ringct20 c1;
    poly_ringct20** t;//[w][M]//TOCORRECT to *t;
    t  = malloc(p->wLen*sizeof(poly_ringct20*));
    for(int i = 0; i < p->wLen; ++i)
        t[i] = malloc(p->M*p->POLY_RINGCT20_SIZE);
    ringct20_unpack_sig(sig->sig_data,aList,&c1, t, &h, p);
    //CRUTCH ADD test pbk in aList
    int pbk_in_aList = 0;
    poly_ringct20 a_pi;
    ringct20_unpack_pbk(public_key->data, &a_pi, p);
    for(int i = 0; i < p->wLen; ++i)
    {
        if(poly_equal(&a_pi, aList + i))
        {
            pbk_in_aList = 1;
            break;
        }
    }

    int result = 1;

    if(pbk_in_aList)
        result = 1 ^ LRCT_SigVer(&c1, t, p->A, p->H, p->mLen, &h, aList, p->wLen, msg, msg_size);


    free(aList);

    for(int i = 0; i < p->wLen; ++i)
        free(t[i]);
    free(t);
    ringct20_params_free(p);
    return result;
}



int ringct20_crypto_sign_keypair(ringct20_public_key_t *pbk, ringct20_private_key_t *prk, DAP_RINGCT20_SIGN_SECURITY kind)
{
    ringct20_param_t *p;
    p = calloc(sizeof (ringct20_param_t),1);
    ringct20_params_init(p, kind);
    if(ringct20_private_and_public_keys_init(prk,pbk,p) != 0)
    {
        ringct20_params_free(p);//free(p);
        return -1;
    }


    poly_ringct20 *S;
    poly_ringct20 *a;
    S = (poly_ringct20*)malloc(sizeof(poly_ringct20)*p->mLen);
    a = (poly_ringct20*)malloc(sizeof(poly_ringct20));

   // LRCT_Setup(A,H,p->mLen);
    LRCT_SampleKey(S, p->mLen);
    LRCT_KeyGen(a, p->A, S, p->mLen);
    ringct20_pack_pbk(pbk->data, a, p);
    ringct20_pack_prk(prk->data, S, p);

    free(S);
    free(a);


    ringct20_params_free(p);
    return 0;

}

void ringct20_private_key_delete(ringct20_private_key_t *private_key)
{

    if(private_key) {
        free(private_key->data);
        private_key->data = NULL;
        free(private_key);
    }
}

void ringct20_public_key_delete(ringct20_public_key_t *public_key)
{
    if(public_key) {
        free(public_key->data);
        public_key->data = NULL;
        free(public_key);
    }
}

void ringct20_private_and_public_keys_delete(ringct20_private_key_t *private_key, ringct20_public_key_t *public_key){

    free(private_key->data);
    private_key->data = NULL;
    free(public_key->data);
    public_key->data = NULL;
}
int32_t ringct20_private_and_public_keys_init(ringct20_private_key_t *private_key, ringct20_public_key_t *public_key, ringct20_param_t *p){

    unsigned char *f = NULL, *g = NULL;

    f = calloc(p->RINGCT20_PBK_SIZE, sizeof(char));
    if (f == NULL) {
        free(f);
//        free(g);
        return -1;
    }
    public_key->kind = p->kind;
    public_key->data = f;

    g = calloc(p->RINGCT20_PRK_SIZE, sizeof(char));
    if (g == NULL) {
        free(f);
        free(g);
        return -1;
    }

    private_key->kind = p->kind;
    private_key->data = g;

    return 0;
}

void dap_enc_sig_ringct20_set_type(DAP_RINGCT20_SIGN_SECURITY type)
{
    _ringct20_type = type;
}

void dap_enc_sig_ringct20_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_SIG_RINGCT20;
    key->enc = NULL;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_ringct20_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_ringct20_verify_sign;
//    key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key) dap_enc_sig_ringct20_get_sign;
//    key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key) dap_enc_sig_ringct20_verify_sign;
}

// generation key pair for sign Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length


void dap_enc_sig_ringct20_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size,
        size_t key_size)
{
//    (void) kex_buf;
//    (void) kex_size;
//    (void) key_size;

    int32_t retcode;

    DAP_RINGCT20_SIGN_SECURITY ringct20_type = RINGCT20_MAXSEC;
    dap_enc_sig_ringct20_set_type(ringct20_type);


    //int32_t type = 2;
    key->priv_key_data_size = sizeof(ringct20_private_key_t);
    key->pub_key_data_size = sizeof(ringct20_public_key_t);
    key->priv_key_data = malloc(key->priv_key_data_size);
    key->pub_key_data = malloc(key->pub_key_data_size);

    retcode = ringct20_crypto_sign_keypair((ringct20_public_key_t *) key->pub_key_data,
            (ringct20_private_key_t *) key->priv_key_data, _ringct20_type);
    if(retcode != 0) {
        ringct20_private_and_public_keys_delete((ringct20_private_key_t *) key->pub_key_data,
                (ringct20_public_key_t *) key->pub_key_data);
        log_it(L_CRITICAL, "Error");
        return;
    }
}

size_t dap_enc_sig_ringct20_get_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(ringct20_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    if(!ringct20_crypto_sign((ringct20_signature_t *) signature, (const unsigned char *) msg, msg_size, key->priv_key_data))
        return signature_size;
    else
        return 0;
}

size_t dap_enc_sig_ringct20_verify_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(ringct20_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    return (ringct20_crypto_sign_open( (unsigned char *) msg, msg_size, (ringct20_signature_t *) signature, key->pub_key_data));
}

void dap_enc_sig_ringct20_key_delete(struct dap_enc_key * key)
{
    ringct20_private_and_public_keys_delete((ringct20_private_key_t *) key->priv_key_data,
            (ringct20_public_key_t *) key->pub_key_data);
}

size_t dap_enc_ringct20_calc_signature_size(void)
{
    return sizeof(ringct20_signature_t);
}

/* Serialize a signature */
uint8_t* dap_enc_ringct20_write_signature(ringct20_signature_t* a_sign, size_t *a_sign_out)
{
    if(!a_sign || *a_sign_out!=sizeof(ringct20_signature_t)) {
        return NULL ;
    }
    size_t l_shift_mem = 0;
    size_t l_buflen = sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY) + a_sign->sig_len + sizeof(unsigned long long);

    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    l_shift_mem += sizeof(size_t);
    memcpy(l_buf + l_shift_mem, &a_sign->kind, sizeof(DAP_RINGCT20_SIGN_SECURITY));
    l_shift_mem += sizeof(DAP_RINGCT20_SIGN_SECURITY);
    memcpy(l_buf + l_shift_mem, &a_sign->sig_len, sizeof(unsigned long long));
    l_shift_mem += sizeof(unsigned long long);
    memcpy(l_buf + l_shift_mem, a_sign->sig_data, a_sign->sig_len );
    l_shift_mem += a_sign->sig_len ;

    if(a_sign_out)
        *a_sign_out = l_buflen;
    return l_buf;
}

/* Deserialize a signature */
ringct20_signature_t* dap_enc_ringct20_read_signature(uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY)))
        return NULL ;
    DAP_RINGCT20_SIGN_SECURITY kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(DAP_RINGCT20_SIGN_SECURITY));
    if(l_buflen != a_buflen)
        return NULL ;
    ringct20_param_t p;
    if(!ringct20_params_init(&p, kind))
        return NULL ;

    ringct20_signature_t* l_sign = DAP_NEW(ringct20_signature_t);
    l_sign->kind = kind;
    size_t l_shift_mem = sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY);
    memcpy(&l_sign->sig_len, a_buf + l_shift_mem, sizeof(unsigned long long));
    l_shift_mem += sizeof(unsigned long long);
    l_sign->sig_data = DAP_NEW_SIZE(unsigned char, l_sign->sig_len);
    memcpy(l_sign->sig_data, a_buf + l_shift_mem, l_sign->sig_len);
    l_shift_mem += l_sign->sig_len;
    return l_sign;
}

/* Serialize a private key. */
uint8_t* dap_enc_ringct20_write_private_key(const ringct20_private_key_t* a_private_key, size_t *a_buflen_out)
{
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if(!ringct20_params_init(p, a_private_key->kind))
    {
        ringct20_params_free(p);

        return NULL;
    }
    size_t l_buflen = sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY) + p->RINGCT20_PRK_SIZE; //CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_private_key->kind, sizeof(DAP_RINGCT20_SIGN_SECURITY));
    memcpy(l_buf + sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY), a_private_key->data, p->RINGCT20_PRK_SIZE);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    ringct20_params_free(p);
    return l_buf;
}

/* Serialize a public key. */
uint8_t* dap_enc_ringct20_write_public_key(const ringct20_public_key_t* a_public_key, size_t *a_buflen_out)
{
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if(!ringct20_params_init(p, a_public_key->kind))
    {
        ringct20_params_free(p);

        return NULL;
    }

    size_t l_buflen = sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY) + p->RINGCT20_PBK_SIZE;//.CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_public_key->kind, sizeof(DAP_RINGCT20_SIGN_SECURITY));
    memcpy(l_buf + sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY), a_public_key->data, p->RINGCT20_PBK_SIZE);//.CRYPTO_PUBLICKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    ringct20_params_free(p);
    return l_buf;
}

/* Deserialize a private key. */
ringct20_private_key_t* dap_enc_ringct20_read_private_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY)))
        return NULL;
    DAP_RINGCT20_SIGN_SECURITY kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(DAP_RINGCT20_SIGN_SECURITY));
    if(l_buflen != a_buflen)
        return NULL;
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if(!ringct20_params_init(p, kind))
    {
        ringct20_params_free(p);

        return NULL;
    }
    ringct20_private_key_t* l_private_key = DAP_NEW(ringct20_private_key_t);
    l_private_key->kind = kind;

    l_private_key->data = DAP_NEW_SIZE(unsigned char, p->RINGCT20_PRK_SIZE);//.CRYPTO_SECRETKEYBYTES);
    memcpy(l_private_key->data, a_buf + sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY), p->RINGCT20_PRK_SIZE);//.CRYPTO_SECRETKEYBYTES);

    ringct20_params_free(p);
    return l_private_key;
}

/* Deserialize a public key. */
ringct20_public_key_t* dap_enc_ringct20_read_public_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY)))
        return NULL;
    DAP_RINGCT20_SIGN_SECURITY kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(DAP_RINGCT20_SIGN_SECURITY));
    if(l_buflen != a_buflen)
        return NULL;
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if(!ringct20_params_init(p, kind))
    {
        ringct20_params_free(p);
        return NULL;
    }
    ringct20_public_key_t* l_public_key = DAP_NEW(ringct20_public_key_t);
    l_public_key->kind = kind;

    l_public_key->data = DAP_NEW_SIZE(unsigned char, p->RINGCT20_PBK_SIZE);//.CRYPTO_PUBLICKEYBYTES);
    memcpy(l_public_key->data, a_buf + sizeof(size_t) + sizeof(DAP_RINGCT20_SIGN_SECURITY), p->RINGCT20_PBK_SIZE);//.CRYPTO_PUBLICKEYBYTES);
    ringct20_params_free(p);
    return l_public_key;
}
