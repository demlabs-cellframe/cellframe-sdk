#include "dap_common.h"
#include "dap_enc_msrln16.h"

#include "liboqs/crypto/rand/rand.h"
#include "liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h"
#include "liboqs/kex/kex.h"

#define LOG_TAG "dap_enc_msrln16"

OQS_KEX *kex = NULL;

void *alignce_priv = NULL;
uint8_t *alice_msg = NULL;
size_t alice_msg_len;
uint8_t *alice_key = NULL;
size_t alice_key_len;

uint8_t *bob_msg = NULL;
size_t bob_msg_len;
uint8_t *bob_key = NULL;
size_t bob_key_len;

/*struct  dap_enc_param{
    enum OQS_KEX_alg_name alg_name;
    char *named_parameters;
    char *id;
};

typedef struct dap_enc_sidh16_key{
} dap_enc_sidh16_key_t;*/

#define PRINT_HEX_STRING(label, str, len)                        \
    {   size_t i;                                                \
        printf("%-20s (%4zu bytes):  ", (label), (size_t)(len)); \
        for (i = 0; i < (len); i++) {                            \
         printf("%02X", ((unsigned char *) (str))[i]);           \
        }                                                        \
        printf("\n");                                            \
    }


/**
 * @brief dap_enc_msrln16_key_new_generate
 * @param rand
 * @return
 */

size_t dap_enc_msrln16_key_new_generate(struct dap_enc_key* a_key, size_t a_size)//(OQS_RAND* rand)
{
    if (a_key == NULL) {
        return NULL;
    }
    
    a_key->_inheritor = (dap_enc_msrln16_key_t*)malloc(sizeof(dap_enc_msrln16_key_t));

    a_key->type = DAP_ENC_KEY_TYPE_RLWE_MSRLN16;
    a_key->last_used_timestamp;
    dap_enc_msrln16_key_t *msrln16_a_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(a_key);
    msrln16_a_key->private_key = NULL;

    return sizeof(a_key);
}

/**
 * @brief dap_enc_msrln16_key_new_from_data
 * @param k
 * @param alice_priv
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 */

void dap_enc_msrln16_key_new_from_data(OQS_KEX *k, const void * alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len)
{
    /*gen = OQS_KEX_rlwe_msrln16_alice_1(k, alice_priv, bob_msg, bob_msg_len, &alice_key, &alice_key_len);
    if(gen != 1) {
        printf("OQS_KEX_rlwe_msrln16_alice_1 lose..\n");
        gen = 0;
    }
    PRINT_HEX_STRING("Alice session key", alice_key, alice_key_len);

   if(alice_key_len != bob_key_len) {
                printf("ERROR: Alice's session key and Bob's session key are different lengths (%zu vs %zu)\n", alice_key_len, bob_key_len);
                gen = 0;
            }
   gen = memcmp(alice_key, bob_key, alice_key_len);
      if(gen != 0){
          printf("ERROR: Alice's session key and Bob's session key are not equal\n");
          PRINT_HEX_STRING("Alice session key", alice_key, alice_key_len);
          PRINT_HEX_STRING("Bob session key", bob_key, bob_key_len);

          // здесь сделать запись ключа в файл????

          gen = 0;
      }
       printf("Alice and Bob's session keys match.\n");
       printf("\n\n");

      gen = 1;*/

}

/**
 * @brief dap_enc_msrln16_key_new_from_data_public
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_msrln16_key_new_from_data_public(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size)
{

}

OQS_KEX *dap_kex_rlwe_msrln16_new(OQS_RAND *rand){
    return OQS_KEX_rlwe_msrln16_new(rand);
}

int dap_rlwe_msrln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len){
    return OQS_KEX_rlwe_msrln16_alice_0(k, alice_priv, alice_msg, alice_msg_len);
}

int dap_rlwe_msrln16_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len){
    return OQS_KEX_rlwe_msrln16_alice_1(k,alice_priv,bob_msg,bob_msg_len,key,key_len);

}

/**
 * @brief dap_enc_msrln16_key_delete
 * @param a_key
 */
void dap_enc_msrln16_key_delete(struct dap_enc_key* a_key)
{
    //dap_enc_sidh16_key_t *sidh_a_key = DAP_ENC_SIDH16_KEY(a_key);
    dap_enc_msrln16_key_t* msrln_a_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(a_key);
        (void) a_key;
        if(!a_key){
            return;
        }
      /*  oqs_sidh_cln16_curve_free((PCurveIsogenyStruct)sidh_a_key->user_curveIsogeny);
        sidh_a_key->user_curveIsogeny = NULL;*/
        DAP_DELETE(a_key);
 //   free();
    /*free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);*/
    /*if (alice_priv) {*/
        //free(alice_priv);
    /*}*/
    //OQS_KEX k = a_key->
//    if (!k) {
//        return;
//    }
//    free(k->method_name);
//    k->method_name = NULL;
//    free(k);
//    /*OQS_KEX_rlwe_msrln16_alice_priv_free(kex, alignce_priv);
   /* OQS_KEX_rlwe_msrln16_free(kex);*/
}

/**
 * @brief dap_enc_msrln16_key_public_base64
 * @param a_key
 * @return
 */
char* dap_enc_msrln16_key_public_base64(dap_enc_key_t *a_key)
{

}

/**
 * @brief dap_enc_msrln16_key_public_raw
 * @param a_key
 * @param a_key_public
 * @return
 */
size_t dap_enc_msrln16_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public)
{

}

/**
 * @brief dap_enc_msrln16_decode
 * @param k
 * @param alice_msg
 * @param alice_msg_len
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 * @return
 */
//Боб отвечает на приветствие
size_t dap_enc_msrln16_decode(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len)
{
    /*gen=OQS_KEX_rlwe_msrln16_bob(k, alice_msg, alice_msg_len, &bob_msg, &bob_msg_len, &bob_key, &bob_key_len);
    if (gen!=1){
        //потеряли от боба
    }


    PRINT_HEX_STRING("Bob message", bob_msg, bob_msg_len);
    PRINT_HEX_STRING("Bob session key", bob_key, bob_key_len);*/

}

/**
 * @brief dap_enc_msrln16_encode
 * @param k
 * @param alice_priv
 * @param alice_msg
 * @param alice_msg_len
 * @return
 */


//Алиса приветствует
size_t dap_enc_msrln16_encode(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len)
{
    /*gen=OQS_KEX_rlwe_msrln16_alice_0(k ,alice_priv, alice_msg, alice_msg_len);
    if (gen!=1){
        //потеряли от алисы
    }
   PRINT_HEX_STRING("Alice message", alice_msg, alice_msg_len);*/
}
