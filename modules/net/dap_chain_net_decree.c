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
#include "dap_chain_net_srv_stake_pos_delegate.h"



#define LOG_TAG "chain_net_decree"

// private types definition
static struct decree_hh {
    dap_hash_fast_t key;
    bool is_applied;
    dap_chain_datum_decree_t *decree;
    UT_hash_handle hh;
} *s_decree_hh = NULL;

// Private variable


// Private fuctions prototype
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);
static int s_common_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net, dap_chain_t *a_chain, bool a_apply);
static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, bool a_apply);


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
        if (!l_chain->callback_get_poa_certs)
            continue;
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
    DAP_DELETE(l_decree->fee_addr);
    DAP_DELETE(l_decree);

    return 0;
}

int s_decree_verify_tsd(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net)
{
    int ret_val = 0;

    if (!a_decree)
    {
        log_it(L_ERROR,"Invalid arguments.");
        return -107;
    }

    // Process decree
    switch(a_decree->header.type){
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:{
            ret_val = s_common_decree_handler(a_decree, a_net, NULL, false);
            break;
        }
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:{
            ret_val = s_service_decree_handler(a_decree, NULL, false);
        }
        default:
        log_it(L_WARNING,"Decree type is undefined!");
        ret_val = -100;
    }
    return ret_val;
}

int dap_chain_net_decree_verify(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, size_t a_data_size, dap_hash_fast_t *a_decree_hash)
{
    if (a_data_size < sizeof(dap_chain_datum_decree_t)) {
        log_it(L_WARNING, "Decree size is too small");
        return -120;
    }
    if (dap_chain_datum_decree_get_size(a_decree) != a_data_size) {
        log_it(L_WARNING, "Decree size is invalid");
        return -121;
    }
    if (a_decree->header.common_decree_params.net_id.uint64 != a_net->pub.id.uint64) {
        log_it(L_WARNING, "Decree net id is invalid");
        return -122;
    }

    dap_hash_fast_t l_decree_hash;
    dap_hash_fast(a_decree, a_data_size, &l_decree_hash);
    if (a_decree_hash)
        *a_decree_hash = l_decree_hash;
    struct decree_hh *l_decree_hh = NULL;
    HASH_FIND(hh, s_decree_hh, &l_decree_hash, sizeof(dap_hash_fast_t), l_decree_hh);
    if (l_decree_hh)
        return DAP_DECREE_IS_PRESENT;

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
    size_t l_tsd_offset = dap_sign_get_size(l_signs_block);
    size_t l_signs_arr_size = 0;
    dap_sign_t *l_signs_arr = DAP_NEW_Z_SIZE(dap_sign_t, l_tsd_offset);
    memcpy(l_signs_arr, l_signs_block, l_tsd_offset);
    l_signs_arr_size += l_tsd_offset;
    l_signs_count++;
    while (l_tsd_offset < l_signs_size)
    {
        dap_sign_t *cur_sign = (dap_sign_t *)((byte_t*)l_signs_block + l_tsd_offset);
        size_t l_sign_size = dap_sign_get_size(cur_sign);

        if (l_sign_size > a_decree->header.signs_size)
        {
            log_it(L_WARNING,"Sign size greather than decree datum signs size. May be data is corrupted.");
            DAP_DELETE(l_signs_arr);
            return -105;
        }

        dap_sign_t *l_signs_arr_temp = (dap_sign_t *)DAP_REALLOC(l_signs_arr, l_signs_arr_size + l_sign_size);

        if (!l_signs_arr_temp)
        {
            log_it(L_WARNING,"Memory allocate fail");
            DAP_DELETE(l_signs_arr);
            return -105;
        }

        l_signs_arr = l_signs_arr_temp;
        memcpy((byte_t *)l_signs_arr + l_signs_arr_size, cur_sign, l_sign_size);


        l_signs_arr_size += l_sign_size;
        l_tsd_offset += l_sign_size;
        l_signs_count++;
    }

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_arr, l_signs_arr_size, &l_num_of_unique_signs);

    uint16_t l_min_signs = a_net->pub.decree->min_num_of_owners;
    if (l_num_of_unique_signs < l_min_signs) {
        log_it(L_WARNING, "Not enough unique signatures, get %zu from %hu", l_num_of_unique_signs, l_min_signs);
        return -106;
    }

    // Verify all keys and its signatures
    uint16_t l_signs_size_for_current_sign = 0, l_signs_verify_counter = 0;

    for(size_t i = 0; i < l_num_of_unique_signs; i++)
    {
        size_t l_sign_max_size = dap_sign_get_size(l_unique_signs[i]);
        if (s_verify_pkey(l_unique_signs[i], a_net))
        {
            // 3. verify sign
            size_t l_verify_data_size = l_decree->header.data_size + sizeof(dap_chain_datum_decree_t);
            l_decree->header.signs_size = l_signs_size_for_current_sign;
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_decree, l_verify_data_size))
            {
                l_signs_verify_counter++;
            }
        }
            // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
            l_signs_size_for_current_sign += l_sign_max_size;
    }

    l_decree->header.signs_size = l_signs_size_for_current_sign;

    DAP_DELETE(l_signs_arr);
    DAP_DELETE(l_unique_signs);

    if (l_signs_verify_counter < l_min_signs) {
        log_it(L_WARNING,"Not enough valid signatures, get %hu from %hu", l_signs_verify_counter, l_min_signs);
        return -106;
    }

    // check tsd-section
    if (s_decree_verify_tsd(a_decree, a_net))
    {
        log_it(L_WARNING,"TSD checking error. Decree verification failed");
        return -106;
    }

    return 0;
}

int dap_chain_net_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain)
{
    int ret_val = 0;
    dap_chain_net_t *l_net = NULL;

    if (!a_decree_hash || !a_chain)
    {
        log_it(L_ERROR,"Invalid arguments.");
        return -107;
    }

    l_net = dap_chain_net_by_id(a_chain->net_id);

    if (!l_net->pub.decree)
    {
        log_it(L_WARNING,"Decree is not inited!");
        return -108;
    }

    struct decree_hh *l_decree_hh = NULL;
    if (!a_decree) {
        HASH_FIND(hh, s_decree_hh, a_decree_hash, sizeof(dap_hash_fast_t), l_decree_hh);
        if (!l_decree_hh) {
            char *l_decree_hash_str = dap_hash_fast_to_str_new(a_decree_hash);
            log_it(L_WARNING, "Decree with hash %s is not found", l_decree_hash_str);
            DAP_DELETE(l_decree_hash_str);
            return -110;
        }
        if (l_decree_hh->is_applied) {
            log_it(L_WARNING,"Decree already applyed");
            return -111;
        }
    } else {
        l_decree_hh = DAP_NEW_Z(struct decree_hh);
        l_decree_hh->decree = DAP_DUP_SIZE(a_decree, dap_chain_datum_decree_get_size(a_decree));
        l_decree_hh->key = *a_decree_hash;
        HASH_ADD(hh, s_decree_hh, key, sizeof(dap_hash_fast_t), l_decree_hh);
        if (a_decree->header.common_decree_params.chain_id.uint64 != a_chain->id.uint64)
            // Apply it with corresponding anchor
            return ret_val;
    }

    // Process decree
    switch(l_decree_hh->decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        ret_val = s_common_decree_handler(l_decree_hh->decree, l_net, a_chain, true);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        ret_val = s_service_decree_handler(l_decree_hh->decree, a_chain, true);
    default:
        log_it(L_WARNING,"Decree type is undefined!");
        ret_val = -100;
    }

    if (!ret_val)
        l_decree_hh->is_applied = true;
    else
        log_it(L_ERROR,"Decree applying failed!");

    return ret_val;
}

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain)
{
    int ret_val = 0;
    if (!a_chain || !a_chain)
    {
        log_it(L_ERROR, "Bad arguments");
        return -100;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    if (!l_net->pub.decree)
    {
        log_it(L_WARNING,"Decree is not inited!");
        return -108;
    }

    dap_hash_fast_t l_hash = {};
    size_t l_data_size = dap_chain_datum_decree_get_size(a_decree);

    if ((ret_val = dap_chain_net_decree_verify(a_decree, l_net, l_data_size, &l_hash)) != 0) {
        log_it(L_ERROR,"Decree verification failed!");
        return ret_val;
    }

    return dap_chain_net_decree_apply(&l_hash, a_decree, a_chain);
}

dap_chain_datum_decree_t *dap_chain_net_decree_get_by_hash(dap_hash_fast_t *a_hash, bool *is_applied)
{
    struct decree_hh* l_decree_hh = NULL;
    HASH_FIND(hh, s_decree_hh, a_hash, sizeof(dap_hash_fast_t), l_decree_hh);
    if (!l_decree_hh)
        return NULL;

    if (is_applied)
        *is_applied = l_decree_hh->is_applied;

    return l_decree_hh->decree;
}

// Private functions
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net)
{
    bool ret_val = false;
    dap_list_t *b_item = a_net->pub.decree->pkeys;
    while (b_item && !ret_val)
    {
        dap_pkey_t *l_pkey = (dap_pkey_t*)(b_item->data);

        if (!memcmp(a_sign->pkey_n_sign, l_pkey->pkey, a_sign->header.sign_pkey_size))
        {
            ret_val = true;
        }

        b_item = b_item->next;
    }
    return ret_val;
}

static int s_common_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net, dap_chain_t *a_chain, bool a_apply)
{
    uint256_t l_uint256_buffer;
    uint16_t l_uint16_buffer;
    dap_chain_addr_t l_addr = {}; //????????
    dap_hash_fast_t l_hash = {};
    dap_chain_node_addr_t l_node_addr = {};
    dap_chain_net_t *l_net = a_net;
    dap_list_t *l_owners_list = NULL;

    if (a_apply && !a_chain){
        log_it(L_WARNING, "a_chain must not be NULL");
        return -112;
    }

    switch (a_decree->header.sub_type)
    {
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
                if(dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)){
                    if(l_net->pub.decree->fee_addr != NULL)
                    {
                        l_addr = *l_net->pub.decree->fee_addr;
                    } else
                    {
                        log_it(L_WARNING, "Fee wallet address not set.");
                        return -111;
                    }
                } else{
                    dap_chain_addr_t *l_decree_addr = DAP_NEW_Z_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
                    memcpy(l_decree_addr, &l_addr, sizeof(dap_chain_addr_t));
                    l_net->pub.decree->fee_addr = l_decree_addr;
                }

                if (!dap_chain_datum_decree_get_fee(a_decree, &l_uint256_buffer)){
                    if (!a_apply)
                        break;

                    if (!dap_chain_net_tx_add_fee(a_chain->net_id, l_uint256_buffer, l_addr)) {
                        log_it(L_WARNING,"Can't add/replace fee value.");
                        return -102;
                    }
                }else{
                    log_it(L_WARNING,"Can't get fee value from decree.");
                    return -103;
                }
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            l_owners_list = dap_chain_datum_decree_get_owners(a_decree, &l_uint16_buffer);
            if (!l_owners_list){
                log_it(L_WARNING,"Can't get ownners from decree.");
                return -104;
            }

            if (!a_apply)
                break;

            l_net->pub.decree->num_of_owners = l_uint16_buffer;
            dap_list_free_full(l_net->pub.decree->pkeys, NULL);

            l_net->pub.decree->pkeys = l_owners_list;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
            if (dap_chain_datum_decree_get_min_owners(a_decree, &l_uint16_buffer)){
                log_it(L_WARNING,"Can't get min number of ownners from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            l_net->pub.decree->min_num_of_owners = l_uint16_buffer;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:
            if (dap_chain_datum_decree_get_stake_tx_hash(a_decree, &l_hash)){
                log_it(L_WARNING,"Can't get tx hash from decree.");
                return -105;
            }
            if (dap_chain_datum_decree_get_stake_value(a_decree, &l_uint256_buffer)){
                log_it(L_WARNING,"Can't get stake value from decree.");
                return -105;
            }
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -105;
            }
            if (dap_chain_datum_decree_get_stake_signer_node_addr(a_decree, &l_node_addr)){
                log_it(L_WARNING,"Can't get signer node address from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_key_delegate(l_net, &l_addr, &l_hash, l_uint256_buffer, &l_node_addr);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE:
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_key_invalidate(&l_addr);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE:
            if (dap_chain_datum_decree_get_stake_min_value(a_decree, &l_uint256_buffer)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_set_allowed_min_value(l_uint256_buffer);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT:
            if (dap_chain_datum_decree_get_stake_min_signers_count(a_decree, &l_uint256_buffer)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            dap_chain_t *l_chain = a_chain;
            if (!a_chain)
                l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (!l_chain->callback_set_min_validators_count) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            l_chain->callback_set_min_validators_count(a_chain, (uint16_t)dap_chain_uint256_to(l_uint256_buffer));
            break;
        default: return -1;
    }

    return 0;
}

static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, bool a_apply)
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
