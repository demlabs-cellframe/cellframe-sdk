/*
 *
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
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_pkey.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_tx.h"


#define LOG_TAG "chain_net_decree"

// private types definition

// Private variable


// Private fuctions prototype
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);
static int s_common_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain);
static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain);


// Public functions
int dap_chain_net_decree_init(dap_chain_net_t *a_net)
{
    size_t l_auth_certs_count = 0;

    if (!a_net)
    {
        log_it(L_WARNING,"Invalid arguments. a_net must be not NULL");
        return -106;
    }

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

    l_decree->min_num_of_owners = GET_256_FROM_64((uint64_t)l_count_verify);
    l_decree->num_of_owners = GET_256_FROM_64((uint64_t)l_auth_certs_count);
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

int dap_chain_net_decree_verify(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net, uint32_t *a_signs_count, uint32_t *a_signs_verify)
{
    dap_chain_datum_decree_t *l_decree = a_decree;
    // Get pkeys sign from decree datum
    size_t l_signs_size = 0;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = dap_chain_datum_decree_get_signs(l_decree, &l_signs_size);
    if (!l_signs_size || !l_signs_block)
    {
        log_it(L_WARNING,"Decree data sign not found");
        return -100;
    }

    // Concate all signs in array
    uint32_t l_signs_count = 0;
    size_t l_tsd_offset = sizeof(dap_sign_t) + l_signs_block->header.sign_pkey_size + l_signs_block->header.sign_size;
    size_t l_signs_arr_size = 0;
    dap_sign_t *l_signs_arr = DAP_NEW_Z_SIZE(dap_sign_t, l_tsd_offset);
    memcpy(l_signs_arr, l_signs_block, l_tsd_offset);
    l_signs_arr_size += l_tsd_offset;
    l_signs_count++;
    while (l_tsd_offset < l_signs_size)
    {
        dap_sign_t *cur_sign = (dap_sign_t *)(l_signs_block + l_tsd_offset);
        size_t l_sign_size = sizeof(dap_sign_t) + cur_sign->header.sign_pkey_size + cur_sign->header.sign_size;

        if (l_sign_size > a_decree->header.signs_size)
        {
            log_it(L_WARNING,"Sign size greather than decree datum signs size. May be data is corrupted.");
            DAP_DELETE(l_signs_arr);
            return -105;
        }

        dap_sign_t *l_signs_arr_temp = DAP_REALLOC(l_signs_arr, l_signs_arr_size + l_sign_size);

        if (!l_signs_arr_temp)
        {
            log_it(L_WARNING,"Memory allocate fail");
            DAP_DELETE(l_signs_arr);
            return -105;
        }

        l_signs_arr = l_signs_arr_temp;
        memcpy(l_signs_arr + l_signs_arr_size, cur_sign, l_sign_size);


        l_signs_arr_size += l_sign_size;
        l_tsd_offset += l_sign_size;
        l_signs_count++;
    }

    if (a_signs_count)
        *a_signs_count = l_signs_count;

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_arr, l_signs_arr_size, &l_num_of_unique_signs);

    // Verify all keys and its signatures
    uint16_t l_signs_size_for_current_sign = 0;
    for(size_t i = 0; i < l_num_of_unique_signs; i++)
    {
        if (s_verify_pkey(l_unique_signs[i], a_net))
        {
            // 3. verify sign
            size_t l_verify_data_size = l_decree->header.data_size + sizeof(l_decree->header);
            size_t l_sign_max_size = sizeof(dap_sign_t) + l_unique_signs[i]->header.sign_pkey_size + l_unique_signs[i]->header.sign_size;
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_decree, l_verify_data_size))
            {
                if (a_signs_verify)
                    *a_signs_verify++;
            }
            // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
            l_signs_size_for_current_sign += l_sign_max_size;
            l_decree->header.signs_size = l_signs_size_for_current_sign;
        }
    }

    DAP_DELETE(l_signs_arr);
    DAP_DELETE(l_unique_signs);

    return 0;
}

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
    int ret_val = 0;

    if (!a_decree || !a_chain)
    {
        log_it(L_WARNING,"Invalid arguments. a_decree and a_chain must be not NULL");
        return -107;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    if (!l_net->pub.decree)
    {
        log_it(L_WARNING,"Decree is not inited!");
        return -108;
    }


    uint256_t l_min_signs = l_net->pub.decree->min_num_of_owners;
    uint32_t l_num_of_valid_signs = 0, l_num_of_signs = 0;

    if ((ret_val = dap_chain_net_decree_verify(a_decree, l_net, &l_num_of_signs, &l_num_of_valid_signs)) != 0)
        return ret_val;

    uint256_t l_num_of_valid_signs256 = GET_256_FROM_64((uint64_t)l_num_of_valid_signs);
    if (compare256(l_num_of_valid_signs256, l_min_signs) < 0)
    {
        log_it(L_WARNING,"Not enough valid signatures");
        return -106;
    }

    // Process decree
    switch(a_decree->header.type){
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:{
            return s_common_decree_handler(a_decree, a_chain);
            break;
        }
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:{
            return s_service_decree_handler(a_decree, a_chain);
        }
        default:;
    }

    return -100;
}

// Private functions
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net)
{
    bool ret_val = false;
    dap_list_t *b_item = a_net->pub.decree->pkeys;
    char *l_bytearr_pkey_datum_sign = NULL, *l_bytearr_pkey_sign = NULL;
    l_bytearr_pkey_datum_sign = DAP_NEW_Z_SIZE(char, a_sign->header.sign_pkey_size + 1);
    memcpy(l_bytearr_pkey_datum_sign, a_sign->pkey_n_sign, a_sign->header.sign_pkey_size);

    while (b_item->next && !ret_val)
    {
        dap_pkey_t *l_pkey = (dap_pkey_t*)(b_item->data);
        l_bytearr_pkey_sign = DAP_NEW_Z_SIZE(char, l_pkey->header.size + 1);
        memcpy(l_bytearr_pkey_sign, l_pkey->pkey, l_pkey->header.size);

        if (!strcmp(l_bytearr_pkey_datum_sign, l_bytearr_pkey_sign))
        {
            ret_val = true;
        }

        b_item = b_item->next;
        DAP_DELETE(l_bytearr_pkey_sign);
    }
    DAP_DELETE(l_bytearr_pkey_datum_sign);
    return ret_val;
}

static int s_common_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
    uint256_t l_fee, l_min_owners, l_num_of_owners;
    dap_chain_addr_t l_addr; //????????
    dap_chain_net_t *l_net = NULL;
    dap_list_t *l_owners_list = NULL;


    switch (a_decree->header.sub_type)
    {
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
                if (dap_chain_datum_decree_get_fee(a_decree, &l_fee)){
                    if(!dap_chain_net_tx_add_fee(a_chain->net_id, a_chain, &l_fee, &l_addr)){
                        log_it(L_WARNING,"Can't add fee value.");
                        return -102;
                    }
                }else{
                    if(!dap_chain_net_tx_replace_fee(a_chain->net_id, a_chain, &l_fee, &l_addr)){
                        log_it(L_WARNING,"Can't add fee value.");
                        return -103;
                    }
                }
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            l_net = dap_chain_net_by_id(a_chain->net_id);
            l_owners_list = dap_chain_datum_decree_get_owners(a_decree, &l_num_of_owners);
            if (!l_owners_list){
                log_it(L_WARNING,"Can't get ownners from decree.");
                return -104;
            }

            l_net->pub.decree->num_of_owners = l_num_of_owners;
            l_net->pub.decree->pkeys = l_owners_list;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
            if (dap_chain_datum_decree_get_min_owners(a_decree, &l_min_owners)){
                log_it(L_WARNING,"Can't get min number of ownners from decree.");
                return -105;
            }
            l_net->pub.decree->min_num_of_owners = l_min_owners;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_TON_SIGNERS:

            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_TON_SIGNERS_MIN:

            break;
        default: return -1;
    }

    return 0;
}

static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
   // size_t l_datum_data_size = ;
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

    return 0;
}
