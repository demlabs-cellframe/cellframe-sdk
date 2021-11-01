/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "uthash.h"
#include "utlist.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_cert.h"
#include "dap_cert_file.h"
//#include "dap_hash.h"
#define LOG_TAG "dap_cert"


typedef struct dap_sign_item
{
    dap_sign_t * sign;
    struct dap_sign_item * next;
    struct dap_sign_item * prev;
} dap_sign_item_t;

typedef struct dap_cert_item
{
    char name[DAP_CERT_ITEM_NAME_MAX];
    dap_cert_t * cert;
    UT_hash_handle hh;
} dap_cert_item_t;

typedef struct dap_cert_folder
{
    char *name;
    UT_hash_handle hh;
} dap_cert_folder_t;

typedef struct dap_cert_pvt
{
    dap_sign_item_t *signs;
} dap_cert_pvt_t;


#define PVT(a) ( ( dap_cert_pvt_t *)((a)->_pvt) )

static dap_cert_item_t * s_certs = NULL;
static dap_cert_folder_t * s_cert_folders = NULL;

/**
 * @brief dap_cert_init empty stub for certificate init
 * @return
 */
int dap_cert_init()
{
    return 0;
}

/**
 * @brief dap_cert_parse_str_list
 * @param a_certs_str
 * @param a_certs
 * @param a_certs_size_t
 * @return summary size for signatures of all certs in list
 */
size_t dap_cert_parse_str_list(const char * a_certs_str, dap_cert_t *** a_certs, size_t * a_certs_size)
{
    char * l_certs_tmp_ptrs = NULL;
    char * l_certs_str_dup = strdup(a_certs_str);
    char *l_cert_str = strtok_r(l_certs_str_dup, ",", &l_certs_tmp_ptrs);

    // First we just calc items
    while(l_cert_str) {
        l_cert_str = strtok_r(NULL, ",", &l_certs_tmp_ptrs);
        (*a_certs_size)++;
    }
    // init certs array
    dap_cert_t **l_certs;
    *a_certs = l_certs = DAP_NEW_Z_SIZE(dap_cert_t*, (*a_certs_size) * sizeof(dap_cert_t*) );

    // Second pass we parse them all
    strcpy(l_certs_str_dup, a_certs_str);
    l_cert_str = strtok_r(l_certs_str_dup, ",", &l_certs_tmp_ptrs);

    size_t l_certs_pos = 0;
    size_t l_sign_total_size =0;
    while(l_cert_str) {
        // trim whitespace in certificate's name
        l_cert_str = dap_strstrip(l_cert_str);// removes leading and trailing spaces
        // get certificate by name
        l_certs[l_certs_pos] = dap_cert_find_by_name(l_cert_str);
        // if certificate is found
        if(l_certs[l_certs_pos]) {
            l_sign_total_size += dap_cert_sign_output_size(l_certs[l_certs_pos],0);
            l_certs_pos++;
        } else {
            log_it(L_WARNING,"Can't load cert %s",l_cert_str);
            DAP_DELETE(*a_certs);
            *a_certs = NULL;
            *a_certs_size = 0;
            break;
        }
        l_cert_str = strtok_r(NULL, ",", &l_certs_tmp_ptrs);
    }
    free(l_certs_str_dup);
    return  l_sign_total_size;
}



/**
 * @brief dap_cert_sign_output_size
 * @param a_cert
 * @param a_size_wished
 * @return
 */
size_t dap_cert_sign_output_size(dap_cert_t * a_cert, size_t a_size_wished)
{
    return dap_sign_create_output_unserialized_calc_size( a_cert->enc_key,a_size_wished);
}

/**
 * @brief dap_cert_sign_output
 * @param a_cert
 * @param a_data
 * @param a_data_size
 * @param a_output
 * @param a_output_siz
 * @return
 */
/*int dap_cert_sign_output(dap_cert_t * a_cert, const void * a_data, size_t a_data_size,
                                        void * a_output, size_t a_output_size)
{
    return dap_sign_create_output( a_cert->enc_key,a_data,a_data_size,a_output,a_output_size);
}*/

/**
 * @brief dap_cert_sign
 * @param a_cert
 * @param a_data
 * @param a_data_size
 * @param a_output_size_wished
 * @return
 */
dap_sign_t * dap_cert_sign(dap_cert_t * a_cert, const void * a_data
                                       , size_t a_data_size, size_t a_output_size_wished )
{
    dap_sign_t *l_ret = dap_sign_create(a_cert->enc_key, a_data, a_data_size, a_output_size_wished);
    log_it(L_INFO, "Sign sizes: %d %d", l_ret->header.sign_size, l_ret->header.sign_pkey_size);
    return l_ret;
}

/**
 * @brief dap_cert_add_cert_sign
 * @param a_cert
 * @param a_cert_signer
 * @return
 */
int dap_cert_add_cert_sign(dap_cert_t * a_cert, dap_cert_t * a_cert_signer)
{
    if (a_cert->enc_key->pub_key_data_size && a_cert->enc_key->pub_key_data) {
        dap_sign_item_t * l_sign_item = DAP_NEW_Z(dap_sign_item_t);
        l_sign_item->sign = dap_cert_sign (a_cert_signer,a_cert->enc_key->pub_key_data,a_cert->enc_key->pub_key_data_size,0);
        DL_APPEND ( PVT(a_cert)->signs, l_sign_item );
        return 0;
    } else {
        log_it (L_ERROR, "No public key in cert \"%s\" that we are trying to sign with \"%s\"", a_cert->name,a_cert_signer->name);
        return -1;
    }
}


/**
 * @brief dap_cert_generate_mem
 * @param a_cert_name
 * @param a_key_type
 * @return
 */
dap_cert_t * dap_cert_generate_mem_with_seed(const char * a_cert_name, dap_enc_key_type_t a_key_type,
        const void* a_seed, size_t a_seed_size)
{
    dap_enc_key_t *l_enc_key = dap_enc_key_new_generate(a_key_type, NULL, 0, a_seed, a_seed_size, 0);
    if ( l_enc_key ){
        dap_cert_t * l_cert = dap_cert_new(a_cert_name);
        l_cert->enc_key = l_enc_key;
        //log_it(L_DEBUG,"Certificate generated");
        //dap_cert_item_t * l_cert_item = DAP_NEW_Z(dap_cert_item_t);
        //snprintf(l_cert_item->name,sizeof(l_cert_item->name),"%s",a_cert_name);
        //HASH_ADD_STR(s_certs,name,l_cert_item);
        //log_it(L_DEBUG,"Certificate name %s recorded", a_cert_name);
        return l_cert;
    } else {
        log_it(L_ERROR,"Can't generate key in memory!");
        //dap_cert_delete(l_cert);
        return NULL;
    }
}

/**
 * @brief dap_cert_generate_mem
 * @param a_cert_name
 * @param a_key_type
 * @return
 */
dap_cert_t * dap_cert_generate_mem(const char * a_cert_name, dap_enc_key_type_t a_key_type)
{
    return dap_cert_generate_mem_with_seed(a_cert_name, a_key_type, NULL, 0);
}

/**
 * @brief dap_cert_generate
 * @param a_cert_name
 * @param a_file_path
 * @param a_key_type
 * @return
 */
dap_cert_t * dap_cert_generate(const char * a_cert_name
                                           , const char * a_file_path,dap_enc_key_type_t a_key_type )
{
    dap_cert_t * l_cert = dap_cert_generate_mem(a_cert_name,a_key_type);
    if ( l_cert){
        if ( dap_cert_file_save(l_cert, a_file_path) == 0 ){
            return l_cert;
        } else{
            dap_cert_delete(l_cert);
            log_it(L_ERROR, "Can't save certificate to the file!");
            return NULL;
        }
    } else {
        log_it(L_ERROR,"Can't generate certificat in memory!");
    }
    return NULL;
}

/**
 * @brief dap_cert_delete_by_name
 * @param a_cert_name
 */
void dap_cert_delete_by_name(const char * a_cert_name)
{
    dap_cert_t * l_cert = dap_cert_find_by_name(a_cert_name);
    if ( l_cert )
        dap_cert_delete( l_cert );
    else
        log_it(L_WARNING,"Can't find \"%s\" certificate to delete it",a_cert_name);
}

/**
 * @brief dap_cert_find_by_name
 * @param a_cert_name
 * @return
 */
dap_cert_t * dap_cert_find_by_name(const char * a_cert_name)
{
    dap_cert_item_t * l_cert_item = NULL;
    HASH_FIND_STR(s_certs,a_cert_name,l_cert_item);
    if ( l_cert_item ){
        return l_cert_item->cert ;
    } else {
            dap_cert_t *l_cert = NULL;
            uint16_t l_ca_folders_size = 0;
            char **l_ca_folders;
            char *l_cert_path = NULL;
            l_ca_folders = dap_config_get_array_str(g_config, "resources", "ca_folders", &l_ca_folders_size);
            for (uint16_t i = 0; i < l_ca_folders_size; ++i) {
                l_cert_path = dap_strjoin("", l_ca_folders[i], "/", a_cert_name, ".dcert", (char*)NULL);
                l_cert = dap_cert_file_load(l_cert_path);
                if (l_cert) {
                    goto ret;
                }
            }
    ret:
            if (l_cert_path)
                DAP_DELETE(l_cert_path);
            return l_cert;
        }
}

dap_list_t *dap_cert_get_all_mem()
{
    dap_list_t *l_ret = NULL;
    dap_cert_item_t *l_cert_item = NULL, *l_cert_tmp;
    HASH_ITER(hh, s_certs, l_cert_item, l_cert_tmp) {
        l_ret = dap_list_append(l_ret, l_cert_item->cert);
    }
    return l_ret;
}

/**
 * @brief dap_cert_new
 * @param a_name
 * @return
 */
dap_cert_t * dap_cert_new(const char * a_name)
{
    dap_cert_t * l_ret = DAP_NEW_Z(dap_cert_t);
    l_ret->_pvt = DAP_NEW_Z(dap_cert_pvt_t);
    dap_snprintf(l_ret->name,sizeof(l_ret->name),"%s",a_name);

    dap_cert_item_t * l_cert_item = DAP_NEW_Z(dap_cert_item_t);
    dap_snprintf(l_cert_item->name,sizeof(l_cert_item->name),"%s",a_name);
    l_cert_item->cert = l_ret;
    HASH_ADD_STR(s_certs,name,l_cert_item);

    return l_ret;
}

/**
 * @brief s_cert_delete
 * @param a_cert
 */
void dap_cert_delete(dap_cert_t * a_cert)
{
    dap_cert_item_t * l_cert_item = NULL;
    HASH_FIND_STR(s_certs, a_cert->name, l_cert_item);
    if ( l_cert_item ){
         HASH_DEL(s_certs,l_cert_item);
         DAP_DELETE (l_cert_item);
    }

    if( a_cert->enc_key )
        dap_enc_key_delete (a_cert->enc_key );
    if( a_cert->metadata )
        dap_binary_tree_clear(a_cert->metadata);
    if (a_cert->_pvt)
        DAP_DELETE( a_cert->_pvt );
    DAP_DELETE (a_cert );
}

/**
 * @brief dap_cert_add_file
 * @param a_cert_name
 * @param a_folder_path
 * @return
 */
dap_cert_t * dap_cert_add_file(const char * a_cert_name,const char *a_folder_path)
{
    size_t l_cert_path_length = strlen(a_cert_name)+8+strlen(a_folder_path);
    char * l_cert_path = DAP_NEW_Z_SIZE(char,l_cert_path_length);
    dap_snprintf(l_cert_path,l_cert_path_length,"%s/%s.dcert",a_folder_path,a_cert_name);
    if( access( l_cert_path, F_OK ) == -1 ) {
        log_it (L_ERROR, "File %s is not exists! ", l_cert_path);
        DAP_DELETE(l_cert_path);
        exit(-701);
    }
    dap_cert_t * l_cert;
    l_cert = dap_cert_file_load(l_cert_path);
    if (l_cert == NULL){
        log_it (L_ERROR, "File %s is corrupted or wrong format ", l_cert_path);
    }
    DAP_DELETE(l_cert_path);
    return l_cert;
}

/**
 * @brief dap_cert_save_to_folder
 * @param a_cert
 * @param a_file_dir_path
 */
int dap_cert_save_to_folder(dap_cert_t * a_cert, const char *a_file_dir_path)
{
    int ret = 0;
    const char * l_cert_name = a_cert->name;
    size_t l_cert_path_length = strlen(l_cert_name)+8+strlen(a_file_dir_path);
    char * l_cert_path = DAP_NEW_Z_SIZE(char,l_cert_path_length);
    dap_snprintf(l_cert_path,l_cert_path_length,"%s/%s.dcert",a_file_dir_path,l_cert_name);
    ret = dap_cert_file_save(a_cert,l_cert_path);
    DAP_DELETE( l_cert_path);
    return ret;
}

/**
 * @brief dap_cert_to_pkey
 * @param a_cert
 * @return
 */
dap_pkey_t * dap_cert_to_pkey(dap_cert_t * a_cert)
{
    if ( a_cert )
        return dap_pkey_from_enc_key( a_cert->enc_key );
    else
        return NULL;
}

/**
 * @brief dap_cert_compare_with_sign
 * @param a_cert
 * @param a_sign
 * @return
 */
int dap_cert_compare_with_sign (dap_cert_t * a_cert,const dap_sign_t * a_sign)
{
    dap_return_val_if_fail(a_cert && a_cert->enc_key && a_sign, -1);
    if ( dap_sign_type_from_key_type( a_cert->enc_key->type ).type == a_sign->header.type.type ){
        int l_ret;
        size_t l_pub_key_size = 0;
        // serialize public key
        uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_cert->enc_key, &l_pub_key_size);
        if ( l_pub_key_size == a_sign->header.sign_pkey_size){
            l_ret = memcmp ( l_pub_key, a_sign->pkey_n_sign, a_sign->header.sign_pkey_size );
        }else
            l_ret = -2; // Wrong pkey size
        DAP_DELETE(l_pub_key);
        return l_ret;
    }else
        return -1; // Wrong sign type
}



/**
 * @brief dap_cert_count_cert_sign
 * @param a_cert
 * @return
 */
size_t dap_cert_count_cert_sign(dap_cert_t * a_cert)
{
    size_t ret;
    dap_sign_item_t * l_cert_item = NULL;
    DL_COUNT(  PVT(a_cert)->signs,l_cert_item,ret);
    return ret > 0 ? ret : 0 ;
}


/**
 * @brief dap_cert_dump
 * @param a_cert
 */
void dap_cert_dump(dap_cert_t * a_cert)
{
    dap_printf ("Certificate name: %s\n",a_cert->name);
    dap_printf ("Signature type: %s\n", dap_sign_type_to_str( dap_sign_type_from_key_type(a_cert->enc_key->type) ) );
    dap_printf ("Private key size: %zu\n",a_cert->enc_key->priv_key_data_size);
    dap_printf ("Public key size: %zu\n", a_cert->enc_key->pub_key_data_size);
    size_t l_meta_items_cnt = dap_binary_tree_count(a_cert->metadata);
    dap_printf ("Metadata section count: %zu\n", l_meta_items_cnt);
    dap_printf ("Certificates signatures chain size: %zu\n",dap_cert_count_cert_sign (a_cert));
    if (l_meta_items_cnt) {
        printf ("Metadata sections\n");
        dap_list_t *l_meta_list = dap_binary_tree_inorder_list(a_cert->metadata);
        dap_list_t *l_meta_list_item = dap_list_first(l_meta_list);
        while (l_meta_list_item) {
            dap_cert_metadata_t *l_meta_item = (dap_cert_metadata_t *)l_meta_list_item->data;
            char *l_str;
            switch (l_meta_item->type) {
            case DAP_CERT_META_STRING:
                l_str = strndup((char *)l_meta_item->value, l_meta_item->length);
                printf("%s\t%u\t%u\t%s\n", l_meta_item->key, l_meta_item->type, l_meta_item->length, l_str);
                free(l_str);
                break;
            case DAP_CERT_META_INT:
            case DAP_CERT_META_BOOL:
                printf("%s\t%u\t%u\t%u\n", l_meta_item->key, l_meta_item->type, l_meta_item->length, *(uint32_t *)l_meta_item->value);
                break;
            default:
                l_str = l_meta_item->length ? DAP_NEW_Z_SIZE(char, l_meta_item->length * 2 + 1) : NULL;
                dap_bin2hex(l_str, l_meta_item->value, l_meta_item->length);
                printf("%s\t%u\t%u\t%s\n", l_meta_item->key, l_meta_item->type, l_meta_item->length, l_str);
                DAP_DELETE(l_str);
                break;
            }
            l_meta_list_item = l_meta_list_item->next;
        }
        dap_list_free(l_meta_list);
    }
}

/**
 * @brief dap_cert_get_folder
 * @param a_folder_path
 */
const char* dap_cert_get_folder(int a_n_folder_path)
{
    dap_cert_folder_t *l_cert_folder_item = NULL, *l_cert_folder_item_tmp = NULL;
    int l_n_cur_folder_path = 0;
    HASH_ITER(hh, s_cert_folders, l_cert_folder_item, l_cert_folder_item_tmp)
    {
        if(l_cert_folder_item) {
            if(a_n_folder_path == l_n_cur_folder_path)
                return l_cert_folder_item->name;
            l_n_cur_folder_path++;
        }
    }
    return NULL;
}


/**
 * @brief dap_cert_add_folder
 * @param a_folder_path
 */
void dap_cert_add_folder(const char *a_folder_path)
{
    // save dir
    {
        dap_cert_folder_t * l_cert_folder_item = DAP_NEW_Z(dap_cert_folder_t);
        l_cert_folder_item->name = dap_strdup(a_folder_path);
        HASH_ADD_STR(s_cert_folders, name, l_cert_folder_item);
    }
    dap_mkdir_with_parents(a_folder_path);
    DIR * l_dir = opendir(a_folder_path);
    if( l_dir ) {
        struct dirent * l_dir_entry;
        while((l_dir_entry=readdir(l_dir))!=NULL){
            const char * l_filename = l_dir_entry->d_name;
            size_t l_filename_len = strlen (l_filename);
            // Check if its not special dir entries . or ..
            if( strcmp(l_filename,".") && strcmp(l_filename,"..") ){
                // If not check the file's suffix
                const char l_suffix[]=".dcert";
                size_t l_suffix_len = strlen(l_suffix);
                if (strncmp(l_filename+ l_filename_len-l_suffix_len,l_suffix,l_suffix_len) == 0 ){
                    char * l_cert_name = dap_strdup(l_filename);
                    l_cert_name[l_filename_len-l_suffix_len] = '\0'; // Remove suffix
                    // Load the cert file
                    //log_it(L_DEBUG,"Trying to load %s",l_filename);
                    dap_cert_add_file(l_cert_name,a_folder_path);
                    DAP_DELETE(l_cert_name);
                }
            }
        }
        closedir(l_dir);

        log_it(L_NOTICE, "Added folder %s",a_folder_path);
    }else
        log_it(L_WARNING, "Can't add folder %s to cert manager",a_folder_path);
}

dap_cert_metadata_t *dap_cert_new_meta(const char *a_key, dap_cert_metadata_type_t a_type, void *a_value, size_t a_value_size)
{
    if (!a_key || a_type > DAP_CERT_META_CUSTOM || (!a_value && a_value_size)) {
        log_it(L_WARNING, "Incorrect arguments for dap_cert_new_meta()");
        return NULL;
    }
    size_t l_meta_item_size = sizeof(dap_cert_metadata_t) + a_value_size + strlen(a_key) + 1;
    dap_cert_metadata_t *l_new_meta = DAP_NEW_SIZE(void, l_meta_item_size);
    l_new_meta->length = a_value_size;
    l_new_meta->type = a_type;
    memcpy((void *)l_new_meta->value, a_value, a_value_size);
    dap_stpcpy((char *)&l_new_meta->value[a_value_size], a_key);
    l_new_meta->key = (const char *)&l_new_meta->value[a_value_size];
    return l_new_meta;
}

/**
 * @brief dap_cert_add_meta Add metadata to certificate
 * @param a_cert
 * @param a_key
 * @param a_type
 * @param a_value
 * @param a_value_size
 */
void dap_cert_add_meta(dap_cert_t *a_cert, const char *a_key, dap_cert_metadata_type_t a_type, void *a_value, size_t a_value_size)
{
    if (!a_cert) {
        log_it(L_WARNING, "Certificate pointer to add metadata is NULL");
        return;
    }
    dap_cert_metadata_t *l_new_meta = dap_cert_new_meta(a_key, a_type, a_value, a_value_size);
    dap_binary_tree_t *l_new_root = dap_binary_tree_insert(a_cert->metadata, l_new_meta->key, (void *)l_new_meta);
    if (!a_cert->metadata) {
        a_cert->metadata = l_new_root;
    }
}

void dap_cert_add_meta_scalar(dap_cert_t *a_cert, const char *a_key, dap_cert_metadata_type_t a_type, uint64_t a_value, size_t a_value_size)
{
    void *l_value;
    byte_t l_tmp8;
    uint16_t l_tmp16;
    uint32_t l_tmp32;
    uint64_t l_tmp64;
    switch (a_type) {
    case DAP_CERT_META_STRING:
    case DAP_CERT_META_SIGN:
    case DAP_CERT_META_CUSTOM:
        log_it(L_WARNING, "incoorect metadata type for dap_cert_add_meta_scalar()");
        return;
    default:
        switch (a_value_size) {
        case 1:
            l_tmp8 = a_value;
            l_value = &l_tmp8;
            break;
        case 2:
            l_tmp16 = a_value;
            l_value = (void *)&l_tmp16;
            break;
        case 4:
            l_tmp32 = a_value;
            l_value = (void *)&l_tmp32;
            break;
        case 8:
        default:
            l_tmp64 = a_value;
            l_value = (void *)&l_tmp64;
            break;
        }
        break;
    }
    dap_cert_add_meta(a_cert, a_key, a_type, l_value, a_value_size);
}

/**
 * @brief dap_cert_get_meta
 * @param a_cert
 * @param a_field
 */
dap_cert_metadata_t *dap_cert_get_meta(dap_cert_t *a_cert, const char *a_field)
{
    return dap_binary_tree_search(a_cert->metadata, a_field);
}

char *dap_cert_get_meta_string(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return NULL;
    }
    if (l_meta->type != DAP_CERT_META_STRING) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return NULL;
    }
    return strndup((char *)&l_meta->value[0], l_meta->length);
}

bool dap_cert_get_meta_bool(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return -1;
    }
    if (l_meta->type != DAP_CERT_META_BOOL) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return -1;
    }
    if (l_meta->length != sizeof(bool)) {
        log_it(L_DEBUG, "Metadata field corrupted");
    }
    return *(bool *)&l_meta->value[0];
}

int dap_cert_get_meta_int(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return -1;
    }
    if (l_meta->type != DAP_CERT_META_INT) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return -1;
    }
    if (l_meta->length != sizeof(int)) {
        log_it(L_DEBUG, "Metadata field corrupted");
    }
    return *(int *)&l_meta->value[0];
}

time_t dap_cert_get_meta_time(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return -1;
    }
    if (l_meta->type != DAP_CERT_META_DATETIME) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return -1;
    }
    if (l_meta->length != sizeof(time_t)) {
        log_it(L_DEBUG, "Metadata field corrupted");
    }
    return *(time_t *)&l_meta->value[0];
}

time_t dap_cert_get_meta_period(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return -1;
    }
    if (l_meta->type != DAP_CERT_META_DATETIME_PERIOD) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return -1;
    }
    if (l_meta->length != sizeof(time_t)) {
        log_it(L_DEBUG, "Metadata field corrupted");
    }
    return *(time_t *)&l_meta->value[0];
}

dap_sign_t *dap_cert_get_meta_sign(dap_cert_t *a_cert, const char *a_field)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return NULL;
    }
    if (l_meta->type != DAP_CERT_META_SIGN) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return NULL;
    }
    dap_sign_t *l_ret = (dap_sign_t *)&l_meta->value[0];
    if (l_meta->length != dap_sign_get_size(l_ret)) {
        log_it(L_DEBUG, "Metadata field corrupted");
    }
    return l_ret;
}

void *dap_cert_get_meta_custom(dap_cert_t *a_cert, const char *a_field, size_t *a_meta_size_out)
{
    dap_cert_metadata_t *l_meta = dap_cert_get_meta(a_cert, a_field);
    if (!l_meta) {
        return NULL;
    }
    if (l_meta->type != DAP_CERT_META_CUSTOM) {
        log_it(L_DEBUG, "Requested and actual metadata types are not equal");
        return NULL;
    }
    if (a_meta_size_out) {
        *a_meta_size_out = l_meta->length;
    }
    return (void *)&l_meta->value[0];
}

/**
 * @brief dap_cert_deinit
 */
void dap_cert_deinit()
{

}
