/*
 *
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
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
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_pkey.h"
#include "dap_chain_net.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_srv.h"


#define LOG_TAG "chain_net_decree"

// private types definition

// Private variable


// Private fuctions prototype
static bool verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);



// Public functions
int dap_chain_net_decree_init(dap_chain_net_t *a_net)
{
    size_t l_auth_certs_count = 0;

    dap_list_t *l_net_keys = NULL;
    uint16_t l_count_verify = 0;
    for (dap_chain_t *l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next) {
        l_net_keys = l_chain->callback_get_poa_certs(l_chain, &l_auth_certs_count, &l_count_verify);
        if (l_net_keys)
            break;
    }

    if (!l_net_keys || !l_auth_certs_count)
    {
        log_it(L_WARNING,"Certificates for net %s not found.", a_net->pub.name);
        return -1;
    }

    dap_chain_net_decree_t *l_decree = NULL;
    l_decree = DAP_NEW_Z(dap_chain_net_decree_t);

    if (!l_decree)
    {
        log_it(L_WARNING,"Out of memory.");
        return -2;
    }

    l_decree->min_num_of_owners = l_count_verify;
    l_decree->num_of_owners = l_auth_certs_count;
    l_decree->pkeys = l_net_keys;

    a_net->pub.decree = l_decree;

    return 0;
}

int dap_chain_net_decree_deinit(dap_chain_net_t *a_net)
{
    dap_chain_net_decree_t *l_decree = a_net->pub.decree;
    dap_list_free_full(l_decree->pkeys, NULL);
    DAP_DELETE(l_decree);

    return 0;
}

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
    dap_chain_datum_decree_t *l_decree = a_decree;
    // Get pkeys sign from decree datum
    size_t l_signs_size = 0;
    //multiple signs reading from datum
    dap_tsd_t *l_signs_tsd = dap_chain_datum_decree_get_signs(l_decree, &l_signs_size);
    if (!l_signs_size || !l_signs_tsd)
    {
        log_it(L_WARNING,"Decree data sign not found");
        return -100;
    }

    // Concate all signs from tsd in array
    size_t l_tsd_offset = 0;
    dap_sign_t *l_signs_arr = DAP_NEW_Z_SIZE(dap_sign_t, l_signs_tsd->size);
    size_t l_signs_arr_size = 0;
    memcpy(l_signs_arr, l_signs_tsd->data, l_signs_tsd->size);
    l_tsd_offset += l_signs_tsd->size;
    l_signs_arr_size += l_signs_tsd->size;
    while (l_tsd_offset < l_signs_size)
    {
        dap_sign_t *l_signs_arr_temp = DAP_REALLOC(l_signs_arr, l_tsd_offset + l_signs_tsd->size);

        if (!l_signs_arr_temp)
        {
            log_it(L_WARNING,"Memory allocate fail");
            DAP_DELETE(l_signs_arr);
            return -105;
        }

        l_signs_arr = l_signs_arr_temp;
        memcpy(l_signs_arr + l_tsd_offset, l_signs_tsd->data, l_signs_tsd->size);

        l_signs_arr_size += l_signs_tsd->size;
        l_tsd_offset += l_signs_tsd->size;
    }

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_arr, l_signs_arr_size, &l_num_of_unique_signs);

    // Verify all keys and its signatures
    uint16_t l_num_of_valid_signs = 0;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    for(size_t i = 0; i < l_num_of_unique_signs; i++)
    {
        if (verify_pkey(l_unique_signs[i], l_net))
        {
            // 3. verify sign
            size_t l_verify_data_size = l_decree->header.data_size + sizeof(l_decree->header);
            size_t l_sign_max_size = sizeof(dap_sign_t) + l_unique_signs[i]->header.sign_pkey_size + l_unique_signs[i]->header.sign_size;
            // Each sign change the sign_size field by adding its size. So we need to change this field in header for each sign.
            uint16_t l_signs_size_for_current_sign = sizeof(dap_sign_t) * (i+1);
            l_decree->header.signs_size = l_signs_size_for_current_sign;
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_decree, l_verify_data_size))
            {
                l_num_of_valid_signs++;
            }
        }
    }

    // Get minimum number of signs
    dap_chain_net_t *a_net = dap_chain_net_by_id(a_chain->net_id);
    uint16_t l_min_signs = a_net->pub.decree->min_num_of_owners;

    DAP_DELETE(l_signs_arr);
    DAP_DELETE(l_unique_signs);

    if (l_num_of_valid_signs < l_min_signs)
    {
        log_it(L_WARNING,"Not enough valid signatures");
        return -105;
    }

    // Process decree
    switch(l_decree->header.type){
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:{\
            switch (l_decree->header.sub_type)
            {
                case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:


                break;
            default: return -1;
            }
            break;
        }
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:{
//            size_t l_datum_data_size = ;
//            dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get(l_decree->header.srv_id);
//            if(l_srv){
//                if(l_srv->callbacks.decree){
//                    dap_chain_net_t * l_net = dap_chain_net_by_id(a_chain->net_id);
//                    l_srv->callbacks.decree(l_srv,l_net,a_chain,l_decree,l_datum_data_size);
//                 }
//            }else{
//                log_it(L_WARNING,"Decree for unknown srv uid 0x%016"DAP_UINT64_FORMAT_X , l_decree->header.srv_id.uint64);
//                return -103;
//            }
        }
        default:;
    }

    return 0;
}

// Private functions
static bool verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net)
{
    dap_list_t *b_item = a_net->pub.decree->pkeys;
    while (b_item->next)
    {
        for (uint32_t i = 0; i < a_sign->header.sign_pkey_size; i++)
        {
            if (*(byte_t*)(a_sign->pkey_n_sign + i) != *(byte_t*)(b_item->data + i))
                break;
            if (i == a_sign->header.sign_pkey_size - 1)
                return true;
        }

        b_item = a_net->pub.decree->pkeys->next;
    }

    return false;
}
