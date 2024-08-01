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
#include "dap_pkey.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_cs_esbocs.h"

#define LOG_TAG "chain_net_anchor"

typedef struct anchor_table{
    dap_hash_fast_t anchor_hash;
    dap_chain_datum_anchor_t *anchor;
    UT_hash_handle hh;
} anchor_table_t;  

// private function prototypes
static bool s_verify_pubkeys(dap_sign_t *a_sign, dap_sign_t **a_decree_signs, size_t a_num_of_decree_sign);
static inline dap_sign_t *s_concate_all_signs_in_array(dap_sign_t *a_in_signs, size_t a_signs_size, size_t *a_sings_count, size_t *a_signs_arr_size);

static bool s_debug_more = false;

int dap_chain_net_anchor_init() {
    s_debug_more = dap_config_get_item_bool_default(g_config,"chain_net","debug_more", s_debug_more);
}

static int s_anchor_verify(dap_chain_net_t *a_net, dap_chain_datum_anchor_t *a_anchor, size_t a_data_size, bool a_load_mode)
{
    if (a_data_size < sizeof(dap_chain_datum_anchor_t))
        return log_it(L_WARNING, "Anchor size is too small"), -120;

    if (dap_chain_datum_anchor_get_size(a_anchor) != a_data_size)
        return log_it(L_WARNING, "Anchor size is invalid, %lu != %lu", dap_chain_datum_anchor_get_size(a_anchor), a_data_size), -121;

    int ret_val = 0;
    size_t l_signs_size = a_anchor->header.signs_size;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = (dap_sign_t*)(a_anchor->data_n_sign + a_anchor->header.data_size);

    if (!l_signs_size || !l_signs_block)
        return log_it(L_WARNING, "Anchor data sign not found"), -100;

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_block, l_signs_size, &l_num_of_unique_signs);

    if (!l_num_of_unique_signs || !l_unique_signs)
        return log_it(L_WARNING, "No unique signatures!"), -106;
    bool l_sign_authorized = false;
    size_t l_signs_size_original = a_anchor->header.signs_size;
    a_anchor->header.signs_size = 0;
    for (size_t i = 0; i < l_num_of_unique_signs; i++) {
        dap_chain_net_decree_t *l_net_decree = dap_chain_net_get_net_decree(a_net);
        for (dap_list_t *it = l_net_decree->pkeys; it; it = it->next) {
            if (dap_pkey_compare_with_sign(it->data, l_unique_signs[i])) {
                // TODO make signs verification in s_concate_all_signs_in_array to correctly header.signs_size calculation
                size_t l_verify_data_size = a_anchor->header.data_size + sizeof(dap_chain_datum_anchor_t);
                if (dap_sign_verify_all(l_unique_signs[i], l_signs_size_original, a_anchor, l_verify_data_size))
                    continue;
                l_sign_authorized = true;
                break;
            }
        }
        a_anchor->header.signs_size += dap_sign_get_size(l_unique_signs[i]);
        if (l_sign_authorized)
            break;
    }
    DAP_DELETE(l_unique_signs);
    a_anchor->header.signs_size = l_signs_size_original;

    if (!l_sign_authorized) {
        log_it(L_WARNING, "Anchor signs verify failed");
        return -108;
    }

    dap_hash_fast_t l_decree_hash = {};
    dap_chain_datum_decree_t *l_decree = NULL;
    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_decree_hash)) != 0) {
        log_it(L_WARNING, "Can't get hash from anchor data");
        return -106;
    }

    if (a_load_mode)
        return 0;

    bool l_is_applied = false;
    l_decree = dap_chain_net_decree_get_by_hash(a_net, &l_decree_hash, &l_is_applied);
    if (!l_decree) {
        log_it(L_WARNING, "Can't get decree by hash %s", dap_hash_fast_to_str_static(&l_decree_hash));
        return DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE;
    }
    if (l_is_applied) {
        log_it(L_WARNING, "The decree referred to by the anchor has already been applied");
        return -109;
    }

    return 0;
}

// Public functions
int dap_chain_net_anchor_verify(dap_chain_net_t *a_net, dap_chain_datum_anchor_t *a_anchor, size_t a_data_size)
{
   return s_anchor_verify(a_net, a_anchor, a_data_size, false);
}

int dap_chain_net_anchor_load(dap_chain_datum_anchor_t * a_anchor, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash)
{
    int ret_val = 0;

    if (!a_anchor || !a_chain)
    {
        log_it(L_WARNING, "Invalid arguments. a_decree and a_chain must be not NULL");
        return -107;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_chain_net_decree_t *l_net_decree = dap_chain_net_get_net_decree(l_net);
    if (!l_net_decree)
    {
        log_it(L_WARNING, "Decree is not inited!");
        return -108;
    }

    if ((ret_val = s_anchor_verify(l_net, a_anchor, dap_chain_datum_anchor_get_size(a_anchor), true)) != 0)
    {
        log_it(L_WARNING, "Anchor is not pass verification!");
        return ret_val;
    }

    dap_chain_hash_fast_t l_hash = {0};
    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_hash)) != 0)
    {
        log_it(L_WARNING, "Can not find datum hash in anchor data");
        return -109;
    }

    if ((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain)) != 0){
        debug_if(s_debug_more, L_WARNING, "Decree applying failed");
        return ret_val;
    }
        

    anchor_table_t **l_anchors = dap_chain_net_get_anchors(l_net);
    anchor_table_t *l_new_anchor = DAP_NEW_Z(anchor_table_t);
    l_new_anchor->anchor_hash = *a_anchor_hash;
    l_new_anchor->anchor = a_anchor;
    HASH_ADD(hh, *l_anchors, anchor_hash, sizeof(l_new_anchor->anchor_hash), l_new_anchor);

    return ret_val;
}

dap_chain_datum_anchor_t * s_find_previous_anchor(dap_hash_fast_t *a_old_anchor_hash, dap_chain_net_t *a_net)
{
    if (!a_old_anchor_hash || !a_net){
        log_it(L_ERROR,"Params are NULL");
        return NULL;
    }
    
    dap_chain_net_t *l_net = a_net;
    dap_chain_datum_anchor_t * l_ret_anchor = NULL;
    dap_chain_datum_anchor_t *l_old_anchor = NULL;

    anchor_table_t **l_anchors_ptr = dap_chain_net_get_anchors(l_net);
    anchor_table_t *l_anchor = NULL;
    HASH_FIND(hh, *l_anchors_ptr, a_old_anchor_hash, sizeof(*a_old_anchor_hash), l_anchor);
    if (!l_old_anchor){
        log_it(L_WARNING,"Can not find anchor");
        return NULL;
    }

    l_old_anchor = l_anchor->anchor;

    dap_hash_fast_t l_old_decrere_hash = {};
    if (dap_chain_datum_anchor_get_hash_from_data(l_old_anchor, &l_old_decrere_hash) != 0)
        return NULL;
    dap_chain_datum_decree_t *l_old_decree = dap_chain_net_decree_get_by_hash(l_net, &l_old_decrere_hash, NULL);
    uint16_t l_old_decree_type = l_old_decree->header.type;
    uint16_t l_old_decree_subtype = l_old_decree->header.sub_type;

    anchor_table_t *l_anchors = HASH_LAST(*l_anchors_ptr);
    for(; l_anchors; l_anchors = l_anchors->hh.prev){
        size_t l_datums_count = 0;

        dap_chain_datum_anchor_t *l_curr_anchor = l_anchors->anchor;
        dap_hash_fast_t l_hash = {};
        if (dap_chain_datum_anchor_get_hash_from_data(l_curr_anchor, &l_hash) != 0)
            continue;
        
        bool l_is_applied = false;
        dap_chain_datum_decree_t *l_decree = dap_chain_net_decree_get_by_hash(l_net, &l_hash, &l_is_applied);
        if (!l_decree)
            continue;

        if (l_decree->header.type == l_old_decree_type && l_old_decree_type == DAP_CHAIN_DATUM_DECREE_TYPE_COMMON && 
            l_old_decree_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE &&
            l_decree->header.sub_type == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE){
            
            dap_chain_addr_t l_addr_old, l_addr_new = {};
            if (dap_chain_datum_decree_get_stake_signing_addr(l_old_decree, &l_addr_old)){
                continue;
            }

            if (dap_chain_datum_decree_get_stake_signing_addr(l_decree, &l_addr_new)){
                continue;
            }

            if(dap_chain_addr_compare(&l_addr_old, &l_addr_new)){
                l_ret_anchor = l_curr_anchor;
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
            break;
            }
        } else if (l_decree->header.type == l_old_decree_type && l_decree->header.sub_type == l_old_decree_subtype){
            // check addr if l_decree type is stake approve
            l_ret_anchor = l_curr_anchor;
            dap_chain_net_decree_reset_applied(l_net, &l_hash);
            break;
        }
        if (l_ret_anchor)
            break;
    }

    return l_ret_anchor;
}

void s_delete_anchor(dap_chain_net_t *a_net, dap_hash_fast_t *a_anchor_hash)
{
    anchor_table_t **l_anchors_ptr = dap_chain_net_get_anchors(a_net);
    anchor_table_t *l_anchor = NULL;
    HASH_FIND(hh, *l_anchors_ptr, a_anchor_hash, sizeof(*a_anchor_hash), l_anchor);
    if(l_anchor){
        HASH_DEL(*l_anchors_ptr, l_anchor);
        DAP_DEL_Z(l_anchor);
    }
}

int dap_chain_net_anchor_unload(dap_chain_datum_anchor_t * a_anchor, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash)
{
    int ret_val = 0;

    if (!a_anchor || !a_chain)
    {
        log_it(L_WARNING,"Invalid arguments. a_decree and a_chain must be not NULL");
        return -107;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    if (!dap_chain_net_get_net_decree(l_net))
    {
        log_it(L_WARNING,"Decree is not inited!");
        return -108;
    }

    ret_val = s_anchor_verify(l_net, a_anchor, dap_chain_datum_anchor_get_size(a_anchor), true);

    if (ret_val != 0)
    {
        log_it(L_WARNING,"Decree is not pass verification!");
        return ret_val;
    }

    dap_hash_fast_t l_hash = {};
    if (dap_chain_datum_anchor_get_hash_from_data(a_anchor, &l_hash) != 0)
        return -110;
            
    dap_chain_datum_decree_t *l_decree = dap_chain_net_decree_get_by_hash(l_net, &l_hash, NULL);
    if (!l_decree)
        return -111;

    if(l_decree->header.type == DAP_CHAIN_DATUM_DECREE_TYPE_COMMON){
        switch (l_decree->header.sub_type)
        {
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:{
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                dap_chain_datum_anchor_t * l_new_anchor = s_find_previous_anchor(a_anchor_hash, l_net);
                s_delete_anchor(l_net, a_anchor_hash);
                if (l_new_anchor){// if previous anchor is founded apply it
                    dap_chain_hash_fast_t l_hash = {0};
                    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(l_new_anchor, &l_hash)) != 0){
                        log_it(L_WARNING,"Can not find datum hash in anchor data");
                        return -109;
                    }

                    if((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain))!=0){
                        log_it(L_WARNING,"Decree applying failed");
                        return ret_val;
                    }
                } else {
                    dap_chain_addr_t a_addr = c_dap_chain_addr_blank;
                    if (!dap_chain_net_tx_set_fee(a_chain->net_id, uint256_0, a_addr)){
                        log_it(L_ERROR, "Can't set fee value for network %s", dap_chain_net_by_id(a_chain->net_id)->pub.name);
                        ret_val = -100;
                    }
                }
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:{
                // Invalidate canceled stake
                dap_chain_addr_t l_signing_addr = {};
                if ((ret_val = dap_chain_datum_decree_get_stake_signing_addr(l_decree, &l_signing_addr)) != 0){
                log_it(L_WARNING,"Can't get signing address from decree.");
                    return -105;
                }
                dap_chain_net_srv_stake_key_invalidate(&l_signing_addr);
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                s_delete_anchor(l_net, a_anchor_hash);
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE:{
                // Find previous anchor with this stake approve and apply it 
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                dap_chain_datum_anchor_t * l_new_anchor = s_find_previous_anchor(a_anchor_hash, l_net);
                s_delete_anchor(l_net, a_anchor_hash);
                if (l_new_anchor){// if previous anchor is founded apply it
                    dap_chain_hash_fast_t l_hash = {0};
                    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(l_new_anchor, &l_hash)) != 0){
                        log_it(L_WARNING,"Can not find datum hash in anchor data");
                        return -109;
                    }
                    if((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain))!=0){
                        log_it(L_WARNING,"Decree applying failed");
                        return ret_val;
                    }
                }
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE:{
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                dap_chain_datum_anchor_t * l_new_anchor = s_find_previous_anchor(a_anchor_hash, l_net);
                s_delete_anchor(l_net, a_anchor_hash);
                if (l_new_anchor){// if previous anchor is founded apply it
                    dap_chain_hash_fast_t l_hash = {0};
                    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(l_new_anchor, &l_hash)) != 0){
                        log_it(L_WARNING,"Can not find datum hash in anchor data");
                        return -109;
                    }
                    if((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain))!=0){
                        log_it(L_WARNING,"Decree applying failed");
                        return ret_val;
                    }
                } else {
                    dap_chain_addr_t a_addr = {};
                    dap_chain_net_srv_stake_set_allowed_min_value(a_chain->net_id, dap_chain_coins_to_balance("1.0"));
                }
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT:{
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                dap_chain_datum_anchor_t * l_new_anchor = s_find_previous_anchor(a_anchor_hash, l_net);
                s_delete_anchor(l_net, a_anchor_hash);
                if (l_new_anchor){// if previous anchor is founded apply it
                    dap_chain_hash_fast_t l_hash = {0};
                    if ((ret_val = dap_chain_datum_anchor_get_hash_from_data(l_new_anchor, &l_hash)) != 0){
                        log_it(L_WARNING,"Can not find datum hash in anchor data");
                        return -109;
                    }

                    if((ret_val = dap_chain_net_decree_apply(&l_hash, NULL, a_chain))!=0){
                        log_it(L_WARNING,"Decree applying failed");
                        return ret_val;
                    }
                } else {
                    dap_chain_esbocs_set_min_validators_count(a_chain, 0);                    
                }
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD:{
                // find previous anchor with rewarrd and apply it
                dap_chain_net_decree_reset_applied(l_net, &l_hash);
                dap_chain_net_remove_last_reward(dap_chain_net_by_id(a_chain->net_id));
                s_delete_anchor(l_net, a_anchor_hash);
            }
            break;
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN:
            case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN:
                ret_val = -1;
            default:
                break;
        }
    } else if(l_decree->header.type == DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE){

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
