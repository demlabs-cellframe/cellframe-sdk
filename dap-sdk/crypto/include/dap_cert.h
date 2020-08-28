/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_sign.h"
#include "dap_pkey.h"
#include "dap_binary_tree.h"
#include "dap_enc.h"
#include "dap_enc_key.h"

#define DAP_CERT_ITEM_NAME_MAX 40

typedef enum dap_cert_metadata_type {
    DAP_CERT_META_STRING,
    DAP_CERT_META_BOOL,
    DAP_CERT_META_INT,
    DAP_CERT_META_DATETIME,
    DAP_CERT_META_DATETIME_PERIOD,
    DAP_CERT_META_SIGN,
    DAP_CERT_META_CUSTOM
} dap_cert_metadata_type_t;

typedef struct dap_cert_metadata {
    const char *key;
    uint32_t length;
    dap_cert_metadata_type_t type : 8;
    byte_t value[];
} dap_cert_metadata_t;

typedef struct dap_cert {
    dap_enc_key_t * enc_key;
    char name[DAP_CERT_ITEM_NAME_MAX];
    void * _pvt;
    dap_binary_tree_t * metadata;
} dap_cert_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_cert_init();


dap_cert_t * dap_cert_new(const char * a_name);

size_t dap_cert_parse_str_list(const char * a_certs_str, dap_cert_t *** a_certs, size_t * a_certs_size);

dap_cert_t * dap_cert_generate(const char * a_cert_name,const char * a_file_path,dap_enc_key_type_t a_key_type );

dap_cert_t * dap_cert_generate_mem_with_seed(const char * a_cert_name, dap_enc_key_type_t a_key_type,
        const void* a_seed, size_t a_seed_size);
dap_cert_t * dap_cert_generate_mem(const char * a_cert_name, dap_enc_key_type_t a_key_type );


dap_cert_t * dap_cert_add_file(const char * a_cert_name,const char *a_folder_path);
int dap_cert_save_to_folder(dap_cert_t * a_cert, const char *a_file_dir_path);
const char* dap_cert_get_folder(int a_n_folder_path);
void dap_cert_add_folder(const char *a_folder_path);
void dap_cert_dump(dap_cert_t * a_cert);
dap_pkey_t * dap_cert_to_pkey(dap_cert_t * a_cert);

dap_cert_t * dap_cert_find_by_name(const char * a_cert_name);
dap_list_t *dap_cert_get_all_mem();

dap_sign_t * dap_cert_sign(dap_cert_t * a_cert, const void * a_data, size_t a_data_size, size_t a_output_size_wished );

int dap_cert_compare_with_sign (dap_cert_t * a_cert,const dap_sign_t * a_sign);


size_t dap_cert_sign_output_size(dap_cert_t * a_cert, size_t a_size_wished);


//int dap_cert_sign_output(dap_cert_t * a_cert, const void * a_data, size_t a_data_size
//                                        , void * a_output , size_t a_output_size);


int dap_cert_add_cert_sign(dap_cert_t * a_cert, dap_cert_t * a_cert_signer);

size_t dap_cert_count_cert_sign(dap_cert_t * a_cert);

void dap_cert_deinit();

void dap_cert_delete(dap_cert_t * a_cert);
void dap_cert_delete_by_name(const char * a_cert_name);

dap_cert_metadata_t *dap_cert_new_meta(const char *a_key, dap_cert_metadata_type_t a_type, void *a_value, size_t a_value_size);
void dap_cert_add_meta(dap_cert_t *a_cert, const char *a_key, dap_cert_metadata_type_t a_type, void *a_value, size_t a_value_size);
void dap_cert_add_meta_scalar(dap_cert_t *a_cert, const char *a_key, dap_cert_metadata_type_t a_type, uint64_t a_value, size_t a_value_size);
#define dap_cert_add_meta_string(a_cert, a_key, a_str) dap_cert_add_meta(a_cert, a_key, DAP_CERT_META_STRING, (void *)a_str, strlen(a_str))
#define dap_cert_add_meta_sign(a_cert, a_key, a_sign) dap_cert_add_meta(a_cert, a_key, DAP_CERT_META_SIGN, (void *)a_sign, dap_sign_get_size(a_sign))
#define dap_cert_add_meta_custom(a_cert, a_key, a_val, a_size) dap_cert_add_meta(a_cert, a_key, DAP_CERT_META_CUSTOM, a_val, a_size)
#define dap_cert_add_meta_bool(a_cert, a_key, a_bool) dap_cert_add_meta_scalar(a_cert, a_key, DAP_CERT_META_BOOL, a_bool, sizeof(bool))
#define dap_cert_add_meta_int(a_cert, a_key, a_int) dap_cert_add_meta_scalar(a_cert, a_key, DAP_CERT_META_INT, a_int, sizeof(int))
#define dap_cert_add_meta_time(a_cert, a_key, a_time) dap_cert_add_meta_scalar(a_cert, a_key, DAP_CERT_META_DATETIME, a_time, sizeof(time_t))
#define dap_cert_add_meta_period(a_cert, a_key, a_period) dap_cert_add_meta_scalar(a_cert, a_key, DAP_CERT_META_DATETIME_PERIOD, a_period, sizeof(time_t))

char *dap_cert_get_meta_string(dap_cert_t *a_cert, const char *a_field);
bool dap_cert_get_meta_bool(dap_cert_t *a_cert, const char *a_field);
int dap_cert_get_meta_int(dap_cert_t *a_cert, const char *a_field);
time_t dap_cert_get_meta_time(dap_cert_t *a_cert, const char *a_field);
time_t dap_cert_get_meta_period(dap_cert_t *a_cert, const char *a_field);
dap_sign_t *dap_cert_get_meta_sign(dap_cert_t *a_cert, const char *a_field);
void *dap_cert_get_meta_custom(dap_cert_t *a_cert, const char *a_field, size_t *a_meta_size_out);

#ifdef __cplusplus
}
#endif
