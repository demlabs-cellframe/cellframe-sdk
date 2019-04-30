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

#include "uthash.h"
#include "utlist.h"
#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_chain_cert.h"
#include "dap_chain_cert_file.h"
//#include "dap_hash.h"
#define LOG_TAG "dap_chain_cert"


typedef struct dap_chain_sign_item
{
    dap_chain_sign_t * sign;
    struct dap_chain_sign_item * next;
    struct dap_chain_sign_item * prev;
} dap_chain_sign_item_t;

typedef struct dap_chain_cert_item
{
    char name[DAP_CHAIN_CERT_ITEM_NAME_MAX];
    dap_chain_cert_t * cert;
    UT_hash_handle hh;
} dap_chain_cert_item_t;

typedef struct dap_chain_cert_pvt
{
    dap_chain_sign_item_t *signs;
} dap_chain_cert_pvt_t;


#define PVT(a) ( ( dap_chain_cert_pvt_t *)(a->_pvt) )

static dap_chain_cert_item_t * s_certs = NULL;

dap_chain_cert_t * dap_chain_cert_new(const char * a_name);
void dap_chain_cert_delete(dap_chain_cert_t * a_cert);
/**
 * @brief dap_chain_cert_init
 * @return
 */
int dap_chain_cert_init()
{
    return 0;
}

/**
 * @brief dap_chain_cert_sign_output_size
 * @param a_cert
 * @param a_size_wished
 * @return
 */
size_t dap_chain_cert_sign_output_size(dap_chain_cert_t * a_cert, size_t a_size_wished)
{
    return dap_chain_sign_create_output_cals_size( a_cert->enc_key,a_size_wished);
}

/**
 * @brief dap_chain_cert_to_addr
 * @param a_cert
 * @param a_net_id
 * @return
 */
dap_chain_addr_t * dap_chain_cert_to_addr(dap_chain_cert_t * a_cert, dap_chain_net_id_t a_net_id)
{
    dap_chain_addr_t * l_addr = DAP_NEW_Z(dap_chain_addr_t);
    dap_chain_addr_fill(l_addr, a_cert->enc_key, &a_net_id);
    return l_addr;
}

/**
 * @brief dap_chain_cert_sign_output
 * @param a_cert
 * @param a_data
 * @param a_data_size
 * @param a_output
 * @param a_output_siz
 * @return
 */
/*int dap_chain_cert_sign_output(dap_chain_cert_t * a_cert, const void * a_data, size_t a_data_size,
                                        void * a_output, size_t a_output_size)
{
    return dap_chain_sign_create_output( a_cert->enc_key,a_data,a_data_size,a_output,a_output_size);
}*/

/**
 * @brief dap_chain_cert_sign
 * @param a_cert
 * @param a_data
 * @param a_data_size
 * @param a_output_size_wished
 * @return
 */
dap_chain_sign_t * dap_chain_cert_sign(dap_chain_cert_t * a_cert, const void * a_data
                                       , size_t a_data_size, size_t a_output_size_wished )
{
    dap_enc_key_t * l_key = a_cert->enc_key;
    dap_chain_sign_t *l_ret = dap_chain_sign_create(l_key, a_data, a_data_size, a_output_size_wished);
    return l_ret;
}

/**
 * @brief dap_chain_cert_add_cert_sign
 * @param a_cert
 * @param a_cert_signer
 * @return
 */
int dap_chain_cert_add_cert_sign(dap_chain_cert_t * a_cert, dap_chain_cert_t * a_cert_signer)
{
    if (a_cert->enc_key->pub_key_data_size && a_cert->enc_key->pub_key_data) {
        dap_chain_sign_item_t * l_sign_item = DAP_NEW_Z(dap_chain_sign_item_t);
        l_sign_item->sign = dap_chain_cert_sign (a_cert_signer,a_cert->enc_key->pub_key_data,a_cert->enc_key->pub_key_data_size,0);
        DL_APPEND ( PVT(a_cert)->signs, l_sign_item );
        return 0;
    } else {
        log_it (L_ERROR, "No public key in cert \"%s\" that we are trying to sign with \"%s\"", a_cert->name,a_cert_signer->name);
        return -1;
    }
}


/**
 * @brief dap_chain_cert_generate_mem
 * @param a_cert_name
 * @param a_key_type
 * @return
 */
dap_chain_cert_t * dap_chain_cert_generate_mem(const char * a_cert_name,
                                               dap_enc_key_type_t a_key_type )
{
    dap_enc_key_t *l_enc_key = dap_enc_key_new_generate(a_key_type, NULL, 0, NULL, 0, 0);
    if ( l_enc_key ){
        dap_chain_cert_t * l_cert = dap_chain_cert_new(a_cert_name);
        l_cert->enc_key = l_enc_key;
        log_it(L_DEBUG,"Certificate generated");
        //dap_chain_cert_item_t * l_cert_item = DAP_NEW_Z(dap_chain_cert_item_t);
        //snprintf(l_cert_item->name,sizeof(l_cert_item->name),"%s",a_cert_name);
        //HASH_ADD_STR(s_certs,name,l_cert_item);
        log_it(L_DEBUG,"Certificate name %s recorded", a_cert_name);
        return l_cert;
    } else {
        log_it(L_ERROR,"Can't generate key in memory!");
        //dap_chain_cert_delete(l_cert);
        return NULL;
    }
}

/**
 * @brief dap_chain_cert_generate
 * @param a_cert_name
 * @param a_file_path
 * @param a_key_type
 * @return
 */
dap_chain_cert_t * dap_chain_cert_generate(const char * a_cert_name
                                           , const char * a_file_path,dap_enc_key_type_t a_key_type )
{
    dap_chain_cert_t * l_cert = dap_chain_cert_generate_mem(a_cert_name,a_key_type);
    if ( l_cert){
        if ( dap_chain_cert_file_save(l_cert, a_file_path) == 0 ){
            return l_cert;
        } else{
            dap_chain_cert_delete(l_cert);
            log_it(L_ERROR, "Can't save certificate to the file!");
            return NULL;
        }
    } else {
        log_it(L_ERROR,"Can't generate certificat in memory!");
    }
    return NULL;
}

/**
 * @brief dap_chain_cert_delete_by_name
 * @param a_cert_name
 */
void dap_chain_cert_delete_by_name(const char * a_cert_name)
{
    dap_chain_cert_t * l_cert = dap_chain_cert_find_by_name(a_cert_name);
    if ( l_cert )
        dap_chain_cert_delete( l_cert );
    else
        log_it(L_WARNING,"Can't find \"%s\" certificate to delete it",a_cert_name);
}

/**
 * @brief dap_chain_cert_find_by_name
 * @param a_cert_name
 * @return
 */
dap_chain_cert_t * dap_chain_cert_find_by_name(const char * a_cert_name)
{
    dap_chain_cert_item_t * l_cert_item = NULL;
    HASH_FIND_STR(s_certs,a_cert_name,l_cert_item);
    if ( l_cert_item ){
        return l_cert_item->cert ;
    }else
        return NULL;
}


/**
 * @brief dap_chain_cert_new
 * @param a_name
 * @return
 */
dap_chain_cert_t * dap_chain_cert_new(const char * a_name)
{
    dap_chain_cert_t * l_ret = DAP_NEW_Z(dap_chain_cert_t);
    l_ret->_pvt = DAP_NEW_Z(dap_chain_cert_pvt_t);
    snprintf(l_ret->name,sizeof(l_ret->name),"%s",a_name);

    dap_chain_cert_item_t * l_cert_item = DAP_NEW_Z(dap_chain_cert_item_t);
    snprintf(l_cert_item->name,sizeof(l_cert_item->name),"%s",a_name);
    l_cert_item->cert = l_ret;
    HASH_ADD_STR(s_certs,name,l_cert_item);

    return l_ret;
}

/**
 * @brief s_cert_delete
 * @param a_cert
 */
void dap_chain_cert_delete(dap_chain_cert_t * a_cert)
{
    dap_chain_cert_item_t * l_cert_item = NULL;
    HASH_FIND_STR(s_certs, a_cert->name, l_cert_item);
    if ( l_cert_item ){
         HASH_DEL(s_certs,l_cert_item);
         DAP_DELETE (l_cert_item);
    }

    if( a_cert->enc_key )
        dap_enc_key_delete (a_cert->enc_key );
    if( a_cert->metadata )
        DAP_DELETE (a_cert->metadata );
    if (a_cert->_pvt)
        DAP_DELETE( a_cert->_pvt );
    DAP_DELETE (a_cert );
}

/**
 * @brief dap_chain_cert_add_file
 * @param a_cert_name
 * @param a_folder_path
 * @return
 */
dap_chain_cert_t * dap_chain_cert_add_file(const char * a_cert_name,const char *a_folder_path)
{
    size_t l_cert_path_length = strlen(a_cert_name)+8+strlen(a_folder_path);
    char * l_cert_path = DAP_NEW_Z_SIZE(char,l_cert_path_length);
    snprintf(l_cert_path,l_cert_path_length,"%s/%s.dcert",a_folder_path,a_cert_name);
    if( access( l_cert_path, F_OK ) == -1 ) {
        log_it (L_ERROR, "File %s is not exists! ", l_cert_path);
        exit(-701);
    }
    dap_chain_cert_t * l_cert;
    l_cert = dap_chain_cert_file_load(l_cert_path);
    if (l_cert == NULL){
        log_it (L_ERROR, "File %s is corrupted or wrong format ", l_cert_path);
    }
    return l_cert;
}

/**
 * @brief dap_chain_cert_save_to_folder
 * @param a_cert
 * @param a_file_dir_path
 */
int dap_chain_cert_save_to_folder(dap_chain_cert_t * a_cert, const char *a_file_dir_path)
{
    int ret = 0;
    const char * l_cert_name = a_cert->name;
    size_t l_cert_path_length = strlen(l_cert_name)+8+strlen(a_file_dir_path);
    char * l_cert_path = DAP_NEW_Z_SIZE(char,l_cert_path_length);
    snprintf(l_cert_path,l_cert_path_length,"%s/%s.dcert",a_file_dir_path,l_cert_name);
    ret = dap_chain_cert_file_save(a_cert,l_cert_path);
    DAP_DELETE( l_cert_path);
    return ret;
}

/**
 * @brief dap_chain_cert_to_pkey
 * @param a_cert
 * @return
 */
dap_chain_pkey_t * dap_chain_cert_to_pkey(dap_chain_cert_t * a_cert)
{
    if ( a_cert )
        return dap_chain_pkey_from_enc_key( a_cert->enc_key );
    else
        return NULL;
}

/**
 * @brief dap_chain_cert_compare_with_sign
 * @param a_cert
 * @param a_sign
 * @return
 */
int dap_chain_cert_compare_with_sign (dap_chain_cert_t * a_cert,dap_chain_sign_t * a_sign)
{
    if ( dap_chain_sign_type_from_key_type( a_cert->enc_key->type ).type == a_sign->header.type.type ){
        if ( a_cert->enc_key->pub_key_data_size == (size_t) a_sign->header.sign_pkey_size ){
            return memcmp ( a_cert->enc_key->pub_key_data, a_sign->pkey_n_sign,  a_sign->header.sign_pkey_size );
        }else
            return -2; // Wrong pkey size
    }else
        return -1; // Wrong sign type
}



/**
 * @brief dap_chain_cert_count_cert_sign
 * @param a_cert
 * @return
 */
size_t dap_chain_cert_count_cert_sign(dap_chain_cert_t * a_cert)
{
    size_t ret;
    dap_chain_sign_item_t * l_cert_item = NULL;
    DL_COUNT(  PVT(a_cert)->signs,l_cert_item,ret);
    return ret > 0 ? ret : 0 ;
}


/**
 * @brief dap_chain_cert_dump
 * @param a_cert
 */
void dap_chain_cert_dump(dap_chain_cert_t * a_cert)
{
    printf ("Certificate name: %s\n",a_cert->name);
    printf ("Signature type: %s\n", dap_chain_sign_type_to_str( dap_chain_sign_type_from_key_type(a_cert->enc_key->type) ) );
    printf ("Private key size: %lu\n",a_cert->enc_key->priv_key_data_size);
    printf ("Public key size: %lu\n", a_cert->enc_key->pub_key_data_size);
    printf ("Metadata section size: %lu\n",a_cert->metadata?strlen(a_cert->metadata):0);
    printf ("Certificates signatures chain size: %lu\n",dap_chain_cert_count_cert_sign (a_cert));
}


/**
 * @brief dap_chain_cert_add_folder
 * @param a_folder_path
 */
void dap_chain_cert_add_folder(const char *a_folder_path)
{
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
                    log_it(L_DEBUG,"Trying to load %s",l_filename);
                    dap_chain_cert_add_file(l_cert_name,a_folder_path);
                }
            }

        }
        closedir(l_dir);
    }
}

/**
 * @brief dap_chain_cert_deinit
 */
void dap_chain_cert_deinit()
{

}
