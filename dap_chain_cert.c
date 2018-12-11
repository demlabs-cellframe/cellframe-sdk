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
#include <string.h>
#include <stdio.h>
#include "uthash.h"
#include "dap_common.h"
#include "dap_chain_cert.h"
#include "dap_chain_cert_file.h"

#define LOG_TAG "dap_chain_cert"

typedef struct dap_chain_cert_pvt
{

} dap_chain_cert_pvt_t;

#define DAP_CHAIN_CERT_ITEM_NAME_MAX 40

typedef struct dap_chain_cert_item
{
    char name[DAP_CHAIN_CERT_ITEM_NAME_MAX];
    dap_chain_cert_t * cert;
    UT_hash_handle hh;
} dap_chain_cert_item_t;

#define PVT(a) ( ( dap_chain_cert_pvt_t *)(a->_pvt) )

dap_chain_cert_item_t * s_certs = NULL;
dap_chain_cert_t * s_cert_new();
void s_cert_delete(dap_chain_cert_t * a_cert);
/**
 * @brief dap_chain_cert_init
 * @return
 */
int dap_chain_cert_init()
{
    return 0;
}

dap_chain_cert_t * dap_chain_cert_generate(const char * a_cert_name, const char * a_file_path,dap_enc_key_type_t a_key_type )
{
    dap_chain_cert_t * l_cert = s_cert_new();
    l_cert->key_private = dap_enc_key_new_generate(a_key_type, NULL, 0, NULL, 0, 0);

    dap_chain_cert_item_t * l_cert_item = DAP_NEW_Z(dap_chain_cert_item_t);
    snprintf(l_cert_item->name,sizeof(l_cert_item->name),"%s",a_cert_name);
    HASH_ADD_STR(s_certs,name,l_cert_item);

    if ( dap_chain_cert_file_save(l_cert, a_file_path) == 0 ){
        return l_cert;
    } else{
        s_cert_delete(l_cert);
        log_it(L_ERROR, "Can't save certificate to the file!");
        return NULL;
    }
}

/**
 * @brief s_cert_new
 * @return
 */
dap_chain_cert_t * s_cert_new()
{
    dap_chain_cert_t * l_ret = DAP_NEW_Z(dap_chain_cert_t);
    l_ret->_pvt = DAP_NEW_Z(dap_chain_cert_pvt_t);
    return l_ret;
}

/**
 * @brief s_cert_delete
 * @param a_cert
 */
void s_cert_delete(dap_chain_cert_t * a_cert)
{
    DAP_DELETE( a_cert->_pvt );
    DAP_DELETE (a_cert );
}

/**
 * @brief dap_chain_cert_add_file
 * @param a_cert_name
 * @param a_file_path
 * @return
 */
dap_chain_cert_t * dap_chain_cert_add_file(const char * a_cert_name,const char *a_file_path)
{

}

/**
 * @brief dap_chain_cert_add_folder
 * @param a_cert_name_prefix
 * @param a_folder_path
 */
void dap_chain_cert_add_folder(const char * a_cert_name_prefix,const char *a_folder_path)
{

}

/**
 * @brief dap_chain_cert_deinit
 */
void dap_chain_cert_deinit()
{

}
