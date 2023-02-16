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
#include "dap_chain_datum_decree.h"

#define LOG_TAG "chain_net_anchor"

// private function prototypes
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);

// Public functions
int dap_chain_net_anchor_verify(dap_chain_datum_anchor_t * a_anchor, dap_chain_net_t *a_net, uint32_t *a_signs_count, uint32_t *a_signs_verify)
{
    dap_chain_datum_anchor_t *l_anchor = a_anchor;
    // Get pkeys sign from decree datum

    size_t l_signs_size = l_anchor->header.signs_size;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = (dap_sign_t *)((byte_t*)l_anchor->data_n_sign + l_anchor->header.data_size);
    if (!l_signs_size || !l_signs_block)
    {
        log_it(L_WARNING,"Anchor data sign not found");
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

        if (l_sign_size > l_anchor->header.signs_size)
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

    if (a_signs_count)
        *a_signs_count = l_signs_count;

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_arr, l_signs_arr_size, &l_num_of_unique_signs);

    if (l_num_of_unique_signs != l_signs_count)
    {
        log_it(L_WARNING,"Signatures contain duplicate signs.");
        return -105;
    }

    uint256_t l_min_signs = a_net->pub.decree->min_num_of_owners;
    uint256_t l_num_of_valid_signs256 = GET_256_FROM_64((uint64_t)l_num_of_unique_signs);
    if (compare256(l_num_of_valid_signs256, l_min_signs) < 0)
    {
        log_it(L_WARNING,"Not enough unique signatures");
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
            size_t l_verify_data_size = l_anchor->header.data_size + sizeof(dap_chain_datum_anchor_t);
            l_anchor->header.signs_size = l_signs_size_for_current_sign;
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_anchor, l_verify_data_size))
            {
                l_signs_verify_counter++;
            }
        }
            // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
            l_signs_size_for_current_sign += l_sign_max_size;
    }

    l_anchor->header.signs_size = l_signs_size_for_current_sign;

    DAP_DELETE(l_signs_arr);
    DAP_DELETE(l_unique_signs);

    if (a_signs_verify)
        *a_signs_verify = l_signs_verify_counter;

    l_min_signs = a_net->pub.decree->min_num_of_owners;
    l_num_of_valid_signs256 = GET_256_FROM_64((uint64_t)l_signs_verify_counter);
    if (compare256(l_num_of_valid_signs256, l_min_signs) < 0)
    {
        log_it(L_WARNING,"Not enough valid signatures");
        return -106;
    }

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

    if ((ret_val = dap_chain_net_anchor_verify(a_anchor, l_net, NULL, NULL)) != 0)
    {
        log_it(L_WARNING,"Decree is not pass verification!");
        return ret_val;
    }

    dap_chain_datum_decree_t * l_decree = NULL;
    dap_chain_hash_fast_t l_hash = {0};
    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_hash)) != 0)
    {
        log_it(L_WARNING,"Can not find datum hash in anchor data");
        return -109;
    }
    if ((ret_val = dap_chain_net_decree_get_by_hash(l_hash, &l_decree)) != 0)
    {
        log_it(L_WARNING,"Decree is not found.");
        return -110;
    }

    if((ret_val = dap_chain_net_decree_apply(l_decree, a_chain))!=0)
    {
        log_it(L_WARNING,"Decree applying failed");
    }

    DAP_DELETE(l_decree);

    return ret_val;
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
