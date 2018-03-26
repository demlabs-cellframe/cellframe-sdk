#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_enc_sidh16.h"
#include "dap_enc_key.h"

#include "liboqs/kex/kex.h"
#include "liboqs/crypto/rand/rand.h"
#include "liboqs/kex_sidh_cln16/kex_sidh_cln16.h"

OQS_KEX *k = NULL;
int gen;

void *alignce_priv = NULL;
uint8_t *alice_msg = NULL;
size_t alice_msg_len;
uint8_t *alice_key = NULL;
size_t alice_key_len;

uint8_t *bob_msg = NULL;
size_t bob_msg_len;
uint8_t *bob_key = NULL;
size_t bob_key_len;


struct  dap_enc_param{
    enum OQS_KEX_alg_name alg_name;
    char *named_parameters;
    char *id;
};

typedef struct dap_enc_sidh16_key{
} dap_enc_sidh16_key_t;


#define PRINT_HEX_STRING(label, str, len)                        \
    {   size_t i;                                                \
        printf("%-20s (%4zu bytes):  ", (label), (size_t)(len)); \
        for (i = 0; i < (len); i++) {                            \
         printf("%02X", ((unsigned char *) (str))[i]);           \
        }                                                        \
        printf("\n");                                            \
    }

int dap_enc_sidh16_key_new_generate(OQS_RAND *rand, const char *named_parameters) {

    k = OQS_KEX_sidh_cln16_new(rand, named_parameters);
    if(k == NULL) {
        printf("новая пара не сгенерирована \n");
        gen = 0;
    }
        printf("расчёт для обмена ключами методом  %s\n", k->method_name);
}
    /* Alice's initial message */
size_t dap_enc_sidh16_encode(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {
    gen = OQS_KEX_sidh_cln16_alice_0(k, &alice_priv, &alice_msg, &alice_msg_len);
    if(gen != 1) {
        printf("OQS_KEX_sidh_cln16_alice_0 lose..\n");
        gen = 0;
    }
    PRINT_HEX_STRING("Alice message", alice_msg, alice_msg_len);
}

    /* Bob's response */
size_t dap_enc_sidh16_decode(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **bob_key, size_t *bob_key_len) {
    gen = OQS_KEX_sidh_cln16_bob(k, alice_msg, alice_msg_len, &bob_msg, &bob_msg_len, &bob_key, &bob_key_len);
    if(gen != 1){
        printf("OQS_KEX_sidh_cln16_bob lose..\n");
        gen = 0;
    }
    PRINT_HEX_STRING("Bob message", bob_msg, bob_msg_len);
    PRINT_HEX_STRING("Bob session key", bob_key, bob_key_len);
}

    /* Alice processes Bob's response */
void dap_enc_sidh16_key_new_from_data(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {
    gen = OQS_KEX_sidh_cln16_alice_1(k, alice_priv, bob_msg, bob_msg_len, &alice_key, &alice_key_len);
    if(gen != 1) {
        printf("OQS_KEX_sidh_cln16_alice_1 lose..\n");
        gen = 0;
    }
    PRINT_HEX_STRING("Alice session key", alice_key, alice_key_len)


    /*compare session key lengths and values*/
    if(alice_key_len != bob_key_len) {
        printf("ERROR: Alice's session key and Bob's session key are different lengths (%zu vs %zu)\n", alice_key_len, bob_key_len);
        gen = 0;
    }
    gen = memcmp(alice_key, bob_key, alice_key_len);
    if(gen != 0){
        printf("ERROR: Alice's session key and Bob's session key are not equal\n");
        PRINT_HEX_STRING("Alice session key", alice_key, alice_key_len);
        PRINT_HEX_STRING("Bob session key", bob_key, bob_key_len);

        // здесь сделать запись ключа в файл

        gen = 0;
    }
     printf("Alice and Bob's session keys match.\n");
     printf("\n\n");

    gen = 1;
}

void dap_enc_sidh16_key_delete() {
    free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);
    OQS_KEX_sidh_cln16_alice_priv_free(k, alignce_priv);
    OQS_KEX_sidh_cln16_free(k);
}


































