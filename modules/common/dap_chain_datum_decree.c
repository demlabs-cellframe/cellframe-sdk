/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

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

#include <memory.h>
#include <assert.h>
#include "dap_tsd.h"
#include "dap_sign.h"
#include "dap_common.h"
#include "dap_chain_datum_decree.h"


#define LOG_TAG "dap_chain_datum_decree"



dap_sign_t *dap_chain_datum_decree_get_signs(dap_chain_datum_decree_t *a_decree, size_t* a_signs_size)
{
    if (!a_decree)
        return NULL;

    dap_sign_t *l_signs_section = (dap_sign_t *)(a_decree->data_n_signs + a_decree->header.data_size);

    *a_signs_size = a_decree->header.signs_size;

    return l_signs_section;
}

int dap_chain_datum_decree_get_fee(dap_chain_datum_decree_t *a_decree, uint256_t *a_fee_value)
{
    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    if(!a_decree || !a_fee_value){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }
    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t*)a_decree->data_n_signs + l_tsd_offset;
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_fee_value = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_owners_num)
{
    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;
    uint64_t l_owners_num = 0;
    dap_list_t *l_key_list = NULL;
    if(!a_decree || !a_owners_num){
        log_it(L_WARNING,"Wrong arguments");
        return NULL;
    }

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t*)a_decree->data_n_signs + l_tsd_offset;
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return NULL;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER){
            if(!l_key_list){
                l_key_list = dap_list_alloc();
                if (!l_key_list){
                    log_it(L_WARNING,"Memory allocate failed.");
                    dap_list_free_full(l_key_list, NULL);
                    return NULL;
                }
            }

            dap_pkey_t *l_owner_pkey = DAP_NEW_Z(dap_pkey_t);
            if (!l_owner_pkey){
                log_it(L_WARNING,"Memory allocate failed.");
                dap_list_free_full(l_key_list, NULL);
                return NULL;
            }

            if(dap_tsd_size(l_tsd) > sizeof(dap_pkey_t)){
                log_it(L_WARNING,"TSD size not match the dap_pkey_t. Possible data corrupt.");
                dap_list_free_full(l_key_list, NULL);
                DAP_FREE(l_owner_pkey);
                return NULL;
            }

            *l_owner_pkey = dap_tsd_get_scalar(l_tsd, dap_pkey_t);
            l_key_list = dap_list_append(l_key_list, l_owner_pkey);
            l_owners_num++;
        }
        l_tsd_offset += l_tsd_size;
    }
    *a_owners_num = GET_256_FROM_64(l_owners_num);
    return l_key_list;
}

int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_owners_num)
{
    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    if(!a_decree || !a_min_owners_num){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }
    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t*)a_decree->data_n_signs + l_tsd_offset;
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_min_owners_num = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}
