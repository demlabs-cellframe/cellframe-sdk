//
// Created by Евгений Крамсаков on 21.12.2022.
//

#ifndef _FALCON_PARAMS_H
#define _FALCON_PARAMS_H

#include "dap_crypto_common.h"


typedef enum {
    FALCON_COMPRESSED,
    FALCON_PADDED,
    FALCON_CT
} falcon_kind_t;

typedef enum DAP_FALCON_SIGN_DEGREE {
    FALCON_512 = 9, FALCON_1024 = 10
} falcon_sign_degree_t;

typedef enum DAP_FALCON_SIGN_TYPE {
    FALCON_DYNAMIC,
    FALCON_TREE
} falcon_sign_type_t;

typedef struct {
    falcon_kind_t kind;
    falcon_sign_degree_t degree;
    falcon_sign_type_t type;
} falcon_param_t;

typedef struct {
    falcon_kind_t kind;
    falcon_sign_degree_t degree;
    falcon_sign_type_t type;
    unsigned char* data;
} falcon_private_key_t;

typedef struct {
    falcon_kind_t kind;
    falcon_sign_degree_t degree;
    falcon_sign_type_t type;
    unsigned char* data;
} falcon_public_key_t;

typedef struct {
    falcon_kind_t kind;
    falcon_sign_degree_t degree;
    falcon_sign_type_t type;
    uint64_t sig_len;
    unsigned char* sig_data;
} falcon_signature_t;

#ifdef __cplusplus
extern "C" {
#endif

void falcon_private_key_delete(falcon_private_key_t* private_key);
void falcon_public_key_delete(falcon_public_key_t* public_key);
void falcon_private_and_public_keys_delete(falcon_private_key_t* private_key, falcon_public_key_t* public_key);

#ifdef __cplusplus
}
#endif

#endif //CELLFRAME_SDK_FALCON_PARAMS_H
