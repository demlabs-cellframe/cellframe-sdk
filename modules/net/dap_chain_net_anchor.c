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
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_datum_decree.h"

#define LOG_TAG "chain_net_anchor"

// private function prototypes
static bool s_verify_pubkeys(dap_sign_t *a_sign, dap_sign_t **a_decree_signs, size_t a_num_of_decree_sign);
static inline dap_sign_t *s_concate_all_signs_in_array(dap_sign_t *a_in_signs, size_t a_signs_size, size_t *a_sings_count, size_t *a_signs_arr_size);

// Public functions
int dap_chain_net_anchor_verify(dap_chain_datum_anchor_t *a_anchor, size_t a_data_size)
{
    if (a_data_size < sizeof(dap_chain_datum_anchor_t)) {
        log_it(L_WARNING, "Anchor size is too small");
        return -120;
    }
    if (dap_chain_datum_anchor_get_size(a_anchor) != a_data_size) {
        log_it(L_WARNING, "Anchor size is invalid");
        return -121;
    }
    int ret_val = 0;
    size_t l_signs_size = a_anchor->header.signs_size;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = (dap_sign_t *)((byte_t*)a_anchor->data_n_sign + a_anchor->header.data_size);

    if (!l_signs_size || !l_signs_block)
    {
        log_it(L_WARNING,"Anchor data sign not found");
        return -100;
    }
    dap_sign_t *l_signs_arr = NULL;
    size_t l_signs_count = 0;
    size_t l_signs_arr_size = 0;
    l_signs_arr = s_concate_all_signs_in_array(l_signs_block, l_signs_size, &l_signs_count, &l_signs_arr_size);

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_arr, l_signs_arr_size, &l_num_of_unique_signs);

    if (l_num_of_unique_signs != l_signs_count)
    {
        log_it(L_WARNING,"Signatures contain duplicate signs.");
        return -105;
    }

    uint256_t l_num_of_valid_signs256 = GET_256_FROM_64((uint64_t)l_num_of_unique_signs);
    if (compare256(l_num_of_valid_signs256, GET_256_FROM_64((uint64_t)0)) == 0)
    {
        log_it(L_WARNING,"Not enough unique signatures");
        return -106;
    }

    dap_hash_fast_t l_decree_hash = {};
    dap_chain_datum_decree_t *l_decree = NULL;
    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_decree_hash)) != 0)
    {
        DAP_DELETE(l_signs_arr);
        DAP_DELETE(l_unique_signs);
        log_it(L_WARNING,"Can't get hash from anchor data");
        return -106;
    }

    bool l_is_applied = false;
    l_decree = dap_chain_net_decree_get_by_hash(&l_decree_hash, &l_is_applied);
    if (!l_decree)
    {
        DAP_DELETE(l_signs_arr);
        DAP_DELETE(l_unique_signs);
        char *l_decree_hash_str = dap_hash_fast_to_str_new(&l_decree_hash);
        log_it(L_WARNING,"Can't get decree by hash %s", l_decree_hash_str);
        DAP_DELETE(l_decree_hash_str);
        return DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE;
    }

    if (l_is_applied)
    {
        DAP_DELETE(l_signs_arr);
        DAP_DELETE(l_unique_signs);
        log_it(L_WARNING,"The decree referred to by the anchor has already been applied");
        return -109;
    }

    size_t l_decree_signs_size = l_decree->header.signs_size;
    //multiple signs reading from datum
    dap_sign_t *l_decree_signs_block = (dap_sign_t *)((byte_t*)l_decree->data_n_signs + l_decree->header.data_size);

    if (!l_decree_signs_size || !l_decree_signs_block)
    {
        log_it(L_WARNING,"Anchor data sign not found");
        return -100;
    }
    dap_sign_t *l_decree_signs_arr = NULL;
    size_t l_decree_signs_count = 0;
    size_t l_decree_signs_arr_size = 0;
    l_decree_signs_arr = s_concate_all_signs_in_array(l_decree_signs_block, l_decree_signs_size, &l_decree_signs_count, &l_decree_signs_arr_size);

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_decree_signs = 0;
    dap_sign_t **l_unique_decree_signs = dap_sign_get_unique_signs(l_decree_signs_arr, l_decree_signs_arr_size, &l_num_of_unique_decree_signs);

    // Verify all keys and its signatures
    uint16_t l_signs_size_for_current_sign = 0, l_signs_verify_counter = 0;
    for(size_t i = 0; i < l_num_of_unique_signs; i++)
    {
        size_t l_sign_max_size = dap_sign_get_size(l_unique_signs[i]);
        if (s_verify_pubkeys(l_unique_signs[i], l_unique_decree_signs, l_num_of_unique_decree_signs))
        {
            // 3. verify sign
            size_t l_verify_data_size = a_anchor->header.data_size + sizeof(dap_chain_datum_anchor_t);
            a_anchor->header.signs_size = l_signs_size_for_current_sign;
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, a_anchor, l_verify_data_size))
            {
                l_signs_verify_counter++;
            }
        }
            // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
            l_signs_size_for_current_sign += l_sign_max_size;
    }
    a_anchor->header.signs_size = l_signs_size_for_current_sign;
    DAP_DELETE(l_unique_decree_signs);
    DAP_DELETE(l_decree_signs_arr);

    if(!l_signs_verify_counter)
    {
        log_it(L_WARNING,"Anchor signs verify failed");
        return -108;
    }
    DAP_DELETE(l_signs_arr);
    DAP_DELETE(l_unique_signs);

    return 0;
}

int dap_chain_net_anchor_load(dap_chain_datum_anchor_t * a_anchor, dap_chain_t *a_chain)
{
    int ret_val = 0;

    if (!a_anchor || !a_chain)
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

    if ((ret_val = dap_chain_net_anchor_verify(a_anchor, dap_chain_datum_anchor_get_size(a_anchor))) != 0)
    {
        log_it(L_WARNING,"Decree is not pass verification!");
        return ret_val;
    }

    dap_chain_hash_fast_t l_hash = {0};
    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_hash)) != 0)
    {
        log_it(L_WARNING,"Can not find datum hash in anchor data");
        return -109;
    }

    if((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain))!=0)
    {
        log_it(L_WARNING,"Decree applying failed");
    }

    return ret_val;
}

// Private functions
static bool s_verify_pubkeys (dap_sign_t *a_sign, dap_sign_t **a_decree_signs, size_t a_num_of_decree_sign)
{
    bool ret_val = false;

    for(size_t i = 0; i < a_num_of_decree_sign; i++)
    {
        if (!memcmp(a_sign->pkey_n_sign, a_decree_signs[i]->pkey_n_sign, a_sign->header.sign_pkey_size))
        {
            ret_val = true;
            break;
        }
    }

    return ret_val;
}

static inline dap_sign_t *s_concate_all_signs_in_array(dap_sign_t *a_in_signs, size_t a_signs_size, size_t *a_sings_count, size_t *a_signs_arr_size)
{
    if (!a_in_signs)
    {
        log_it(L_WARNING,"Bad arguments");
        return NULL;
    }

    // Concate all signs in array
    uint32_t l_signs_count = 0;
    size_t l_signs_offset = dap_sign_get_size(a_in_signs);
    size_t l_signs_arr_size = 0;
    dap_sign_t *l_signs_arr = DAP_NEW_Z_SIZE(dap_sign_t, l_signs_offset);
    memcpy(l_signs_arr, a_in_signs, l_signs_offset);
    l_signs_arr_size += l_signs_offset;
    l_signs_count++;
    while (l_signs_offset < a_signs_size)
    {
        dap_sign_t *cur_sign = (dap_sign_t *)((byte_t*)a_in_signs + l_signs_offset);
        size_t l_sign_size = dap_sign_get_size(cur_sign);

        if (l_sign_size > a_signs_size)
        {
            log_it(L_WARNING,"Sign size greather than decree datum signs size. May be data is corrupted.");
            DAP_DELETE(l_signs_arr);
            return NULL;
        }

        dap_sign_t *l_signs_arr_temp = (dap_sign_t *)DAP_REALLOC(l_signs_arr, l_signs_arr_size + l_sign_size);

        if (!l_signs_arr_temp)
        {
            log_it(L_WARNING,"Memory allocate fail");
            DAP_DELETE(l_signs_arr);
            return NULL;
        }

        l_signs_arr = l_signs_arr_temp;
        memcpy((byte_t *)l_signs_arr + l_signs_arr_size, cur_sign, l_sign_size);


        l_signs_arr_size += l_sign_size;
        l_signs_offset += l_sign_size;
        l_signs_count++;
    }

    if (a_sings_count)
        *a_sings_count = l_signs_count;

    if(a_signs_arr_size)
        *a_signs_arr_size = l_signs_arr_size;

    return l_signs_arr;
}
