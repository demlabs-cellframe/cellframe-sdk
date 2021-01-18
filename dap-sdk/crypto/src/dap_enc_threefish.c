#include "dap_enc_threefish.h"

#define TF_OK  0;
#define CBC (5);
#define NSUBKEYS (( NROUNDS/4)+1)
#define LWORD ( 8)

#define NBYTESTWEAK ( 16)
#define NBYTES256 ( 32)
#define NBYTES512 ( 64)
#define NBYTES1024 ( 128)

#define NWORDSTWEAK ( 2)
#define NWORDS256 ( 4)
#define NWORDS512 ( 8)
#define NWORDS1024 ( 16)

#define NROUNDS256 ( 72)
#define NROUNDS512 ( 72)
#define NROUNDS1024 ( 80)

#define NWORDSEXPKEY256 (((NROUNDS256/4)+1)*NWORDS256 )
#define NWORDSEXPKEY512 (((NROUNDS512/4)+1)*NWORDS512 )
#define NWORDSEXPKEY1024 (((NROUNDS1024/4)+1)*NWORDS1024 )

#define KS_PARITY ( 0x1BD11BDAA9FC1A22)

#define ENCRYPT (73)
#define DECRYPT (79)

#define CBC_FLAG (89)

typedef struct TFWORKSPACE256 {uint64_t  state[NWORDS256];
                uint64_t       exp_key[NWORDSEXPKEY256];
                uint64_t       exp_tweak[NWORDSTWEAK];
                int encrypt_flag;
                int mode;} TFWORKSPACE256;


enum
    {
//         256 rotation constants
    R_256_0_0=14, R_256_0_1=16,
    R_256_1_0=52, R_256_1_1=57,
    R_256_2_0=23, R_256_2_1=40,
    R_256_3_0= 5, R_256_3_1=37,
    R_256_4_0=25, R_256_4_1=33,
    R_256_5_0=46, R_256_5_1=12,
    R_256_6_0=58, R_256_6_1=22,
    R_256_7_0=32, R_256_7_1=32,

//          512 rotation constants
    R_512_0_0=46, R_512_0_1=36, R_512_0_2=19, R_512_0_3=37,
    R_512_1_0=33, R_512_1_1=27, R_512_1_2=14, R_512_1_3=42,
    R_512_2_0=17, R_512_2_1=49, R_512_2_2=36, R_512_2_3=39,
    R_512_3_0=44, R_512_3_1= 9, R_512_3_2=54, R_512_3_3=56,
    R_512_4_0=39, R_512_4_1=30, R_512_4_2=34, R_512_4_3=24,
    R_512_5_0=13, R_512_5_1=50, R_512_5_2=10, R_512_5_3=17,
    R_512_6_0=25, R_512_6_1=29, R_512_6_2=39, R_512_6_3=43,
    R_512_7_0= 8, R_512_7_1=35, R_512_7_2=56, R_512_7_3=22,

//  1024 round rotation constants
    R1024_0_0=24, R1024_0_1=13, R1024_0_2= 8, R1024_0_3=47, R1024_0_4= 8, R1024_0_5=17, R1024_0_6=22, R1024_0_7=37,
    R1024_1_0=38, R1024_1_1=19, R1024_1_2=10, R1024_1_3=55, R1024_1_4=49, R1024_1_5=18, R1024_1_6=23, R1024_1_7=52,
    R1024_2_0=33, R1024_2_1= 4, R1024_2_2=51, R1024_2_3=13, R1024_2_4=34, R1024_2_5=41, R1024_2_6=59, R1024_2_7=17,
    R1024_3_0= 5, R1024_3_1=20, R1024_3_2=48, R1024_3_3=41, R1024_3_4=47, R1024_3_5=28, R1024_3_6=16, R1024_3_7=25,
    R1024_4_0=41, R1024_4_1= 9, R1024_4_2=37, R1024_4_3=31, R1024_4_4=12, R1024_4_5=47, R1024_4_6=44, R1024_4_7=30,
    R1024_5_0=16, R1024_5_1=34, R1024_5_2=56, R1024_5_3=51, R1024_5_4= 4, R1024_5_5=53, R1024_5_6=42, R1024_5_7=41,
    R1024_6_0=31, R1024_6_1=44, R1024_6_2=47, R1024_6_3=46, R1024_6_4=19, R1024_6_5=42, R1024_6_6=44, R1024_6_7=25,
    R1024_7_0= 9, R1024_7_1=48, R1024_7_2=35, R1024_7_3=52, R1024_7_4=23, R1024_7_5=31, R1024_7_6=37, R1024_7_7=20
    };


int TF_precompute_key_schedule_256(struct dap_enc_key *a_key, TFWORKSPACE256 *a_workspace){}


void dap_enc_threefish_key_new(struct dap_enc_key *a_key){
    a_key->type = DAP_ENC_KEY_TYPE_THREEFISH;
    a_key->priv_key_data = NULL;
    a_key->priv_key_data_size = 0;
    a_key->enc = dap_enc_threefish_encrypt;
    a_key->dec = dap_enc_threefish_decrypt;
}

void dap_enc_threefish_generate(struct dap_enc_key *a_key){
    a_key->priv_key_data_size = THREEFISH_KEY_SIZE + THREEFISH_TWEEK_SIZE;
    a_key->priv_key_data = (uint8_t *)malloc(a_key->priv_key_data_size);
    randombytes(a_key->priv_key_data, (unsigned int)a_key->priv_key_data_size);
}

size_t dap_enc_threefish_encrypt(struct dap_enc_key *a_key, const void *a_in_data, size_t a_size_in_data, void **a_out){
    //Calc output size
    //Precompute key schedule
    //Encrypt
}
size_t dap_enc_threefish_decrypt(struct dap_enc_key *a_key, const void *a_in_data, size_t a_size_in_data, void **a_out){
    //Calc output size
    //Precompute key schedule
    //Decrypt
}
