/*
 *
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.
 *
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
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_pkey.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_net_types.h"
#include "dap_chain_net_utils.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain.h"
#include "dap_json.h"

#define LOG_TAG "dap_ledger_decree"

// Private fuctions prototype
static bool s_verify_pkey (dap_sign_t *a_sign, dap_ledger_t *a_ledger);
static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_ledger_t *a_ledger, bool a_apply, bool a_anchored);
static int s_service_decree_handler(dap_chain_datum_decree_t *a_decree, dap_ledger_t *a_ledger, bool a_apply);

typedef struct dap_ledger_decree_callback_item {
    uint16_t type;
    uint16_t subtype;
    dap_ledger_decree_callback_t callback;
    struct dap_ledger_decree_callback_item *next;
} dap_ledger_decree_callback_item_t;

static dap_ledger_decree_callback_item_t *s_decree_callbacks = NULL;

void dap_ledger_decree_set_callback(uint16_t a_type, uint16_t a_subtype, dap_ledger_decree_callback_t a_callback)
{
    dap_ledger_decree_callback_item_t *l_item = DAP_NEW_Z(dap_ledger_decree_callback_item_t);
    l_item->type = a_type;
    l_item->subtype = a_subtype;
    l_item->callback = a_callback;
    l_item->next = s_decree_callbacks;
    s_decree_callbacks = l_item;
}

// Public functions

void dap_ledger_decree_init(dap_ledger_t *a_ledger) {
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    l_ledger_pvt->decree_min_num_of_signers = a_ledger->poa_keys_min_count;
    l_ledger_pvt->decree_num_of_owners = dap_list_length(a_ledger->poa_keys);
    l_ledger_pvt->decree_owners_pkeys = a_ledger->poa_keys;
    if ( !l_ledger_pvt->decree_owners_pkeys )
        log_it(L_WARNING, "PoA certificates not found for ledger");
}

static int s_decree_clear(dap_ledger_t *a_ledger, dap_chain_id_t a_chain_id)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_cur_decree, *l_tmp;
    pthread_rwlock_wrlock(&l_ledger_pvt->decrees_rwlock);
    // Policy purge should be handled by callback from net module
    // Net module should provide decree purge callback
    HASH_ITER(hh, l_ledger_pvt->decrees, l_cur_decree, l_tmp) {
        if (l_cur_decree->storage_chain_id.uint64 != a_chain_id.uint64)
            continue;
        HASH_DEL(l_ledger_pvt->decrees, l_cur_decree);
        if ( l_cur_decree->decree &&
             !dap_chain_find_by_id(l_cur_decree->decree->header.common_decree_params.net_id,
                                   l_cur_decree->storage_chain_id)->is_mapped )
            DAP_DELETE(l_cur_decree->decree);
        DAP_DELETE(l_cur_decree);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    return 0;
}

int dap_ledger_decree_purge(dap_ledger_t *a_ledger, dap_chain_id_t a_chain_id)
{
    dap_return_val_if_fail(a_ledger, -1);
    int ret = s_decree_clear(a_ledger, a_chain_id);
    dap_list_free_full(PVT(a_ledger)->decree_owners_pkeys, NULL);
    return ret;
}

static int s_decree_verify(dap_ledger_t *a_ledger, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash, bool a_anchored)
{
    if (a_data_size < sizeof(dap_chain_datum_decree_t)) {
        log_it(L_WARNING, "Decree size is too small");
        return -120;
    }
    if (dap_chain_datum_decree_get_size(a_decree) != a_data_size) {
        log_it(L_WARNING, "Decree size is invalid");
        return -121;
    }
    if (a_decree->header.common_decree_params.net_id.uint64 != a_ledger->net_id.uint64) {
        log_it(L_WARNING, "Decree net id is invalid");
        return -122;
    }

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_sought_decree = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    if (l_sought_decree && l_sought_decree->decree) {
        debug_if(g_debug_ledger, L_WARNING, "Decree with hash %s is already present", dap_hash_fast_to_str_static(a_decree_hash));
        return -123;
    }

    // Get pkeys sign from decree datum
    size_t l_signs_size = 0;
    //multiple signs reading from datum
    dap_sign_t *l_signs_block = dap_chain_datum_decree_get_signs(a_decree, &l_signs_size);
    if (!l_signs_size || !l_signs_block)
    {
        log_it(L_WARNING, "Decree data sign not found");
        return -100;
    }

    // Find unique pkeys in pkeys set from previous step and check that number of signs > min
    size_t l_num_of_unique_signs = 0;
    dap_sign_t **l_unique_signs = dap_sign_get_unique_signs(l_signs_block, l_signs_size, &l_num_of_unique_signs);
    uint16_t l_min_signs = l_ledger_pvt->decree_min_num_of_signers;
    if (l_num_of_unique_signs < l_min_signs) {
        log_it(L_WARNING, "Not enough unique signatures, get %zu from %hu", l_num_of_unique_signs, l_min_signs);
        return -106;
    }

    // Verify all keys and its signatures
    uint16_t l_signs_size_for_current_sign = 0, l_signs_verify_counter = 0;
    // Always duplicate for verification as we need to modify the structure temporarily
    dap_chain_datum_decree_t *l_decree = DAP_DUP_SIZE(a_decree, a_data_size);
    l_decree->header.signs_size = 0;
    size_t l_verify_data_size = l_decree->header.data_size + sizeof(dap_chain_datum_decree_t);

    for (size_t i = 0; i < l_num_of_unique_signs; i++) {
        size_t l_sign_max_size = dap_sign_get_size(l_unique_signs[i]);
        if (s_verify_pkey(l_unique_signs[i], a_ledger)) {
            // 3. verify sign
            if(!dap_sign_verify_all(l_unique_signs[i], l_sign_max_size, l_decree, l_verify_data_size))
                l_signs_verify_counter++;
        } else {
            dap_hash_fast_t l_sign_pkey_hash = {0};
            size_t l_pkey_size = 0;
            uint8_t *l_pkey = dap_sign_get_pkey(l_unique_signs[i], &l_pkey_size);
            log_it(L_WARNING, "Signature [%zu] %s failed public key verification.", i, dap_get_data_hash_str(l_pkey, l_pkey_size).s);
        }
        // Each sign change the sign_size field by adding its size after signing. So we need to change this field in header for each sign.
        l_signs_size_for_current_sign += l_sign_max_size;
        l_decree->header.signs_size = l_signs_size_for_current_sign;
    }

    // Always cleanup temporary copy
    DAP_DELETE(l_decree);
    DAP_DELETE(l_unique_signs);

    if (l_signs_verify_counter < l_min_signs) {
        log_it(L_WARNING, "Not enough valid signatures, get %hu from %hu", l_signs_verify_counter, l_min_signs);
        return -107;
    }

    // check tsd-section
    int l_ret = 0;
    switch(a_decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        l_ret = s_common_decree_handler(a_decree, a_ledger, false, a_anchored);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        l_ret = s_service_decree_handler(a_decree, a_ledger, false);
    break;
    default:
        log_it(L_WARNING, "Decree type is undefined!");
        l_ret = -100;
    }
    if (l_ret) {
        log_it(L_WARNING, "TSD checking error. Decree verification failed");
        return l_ret;
    }

    return 0;
}

int dap_ledger_decree_verify(dap_ledger_t *a_ledger, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash)
{
    return s_decree_verify(a_ledger, a_decree, a_data_size, a_decree_hash, false);
}

int dap_ledger_decree_apply(dap_ledger_t *a_ledger, dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t *a_decree, dap_chain_id_t a_chain_id, dap_hash_fast_t *a_anchor_hash)
{
    dap_return_val_if_fail(a_ledger && a_decree_hash && a_chain_id.uint64, -107);
    int ret_val = 0;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_new_decree = NULL;
    unsigned l_hash_value;
    HASH_VALUE(a_decree_hash, sizeof(dap_hash_fast_t), l_hash_value);
    pthread_rwlock_wrlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_hash_value, l_new_decree);
    if (!l_new_decree) {
        l_new_decree = DAP_NEW_Z(dap_ledger_decree_item_t);
        if (!l_new_decree) {
            log_it(L_CRITICAL, "Memory allocation error");
            pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
            return -1;
        }
        l_new_decree->decree_hash = *a_decree_hash;
        l_new_decree->storage_chain_id = a_chain_id;
        HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->decrees, decree_hash, sizeof(dap_hash_fast_t), l_hash_value, l_new_decree);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);

    if (a_anchor_hash) {    // Processing anchor for decree
        if (!l_new_decree->decree) {
            log_it(L_WARNING, "Decree with hash %s is not found", dap_hash_fast_to_str_static(a_decree_hash));
            l_new_decree->wait_for_apply = true;
            return -110;
        }
        if (l_new_decree->is_applied) {
            debug_if(g_debug_ledger, L_WARNING, "Decree with hash %s already applied", dap_hash_fast_to_str_static(a_decree_hash));
            return -111;
        }
    } else {            // Process decree itself
        if (l_new_decree->decree) {
            debug_if(g_debug_ledger, L_WARNING, "Decree with hash %s is already present", dap_hash_fast_to_str_static(a_decree_hash));
            return -123;
        }
        // Always duplicate decree data for storage (chain module manages original memory)
        l_new_decree->decree = DAP_DUP_SIZE(a_decree, dap_chain_datum_decree_get_size(a_decree));
        if (a_decree->header.common_decree_params.chain_id.uint64 != a_chain_id.uint64 && !l_new_decree->wait_for_apply)
            // Apply it with corresponding anchor
            return ret_val;
    }

    // Process decree
    switch(l_new_decree->decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        ret_val = s_common_decree_handler(l_new_decree->decree, a_ledger, true, a_anchor_hash);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        ret_val = s_service_decree_handler(l_new_decree->decree, a_ledger, true);
        break;
    default:
        log_it(L_WARNING,"Decree type is undefined!");
        ret_val = -100;
    }

    if (!ret_val) {
        l_new_decree->is_applied = true;
        l_new_decree->wait_for_apply = false;
        if (a_anchor_hash)
            l_new_decree->anchor_hash = *a_anchor_hash;
    } else
        debug_if(g_debug_ledger, L_ERROR,"Decree applying failed!");

    return ret_val;
}

int dap_ledger_decree_load(dap_ledger_t *a_ledger, dap_chain_datum_decree_t * a_decree, dap_chain_id_t a_chain_id, dap_chain_hash_fast_t *a_decree_hash)
{
    int ret_val = 0;
    if (!a_chain_id.uint64 || !a_decree || !a_ledger) {
        log_it(L_ERROR, "Bad arguments");
        return -100;
    }

    size_t l_data_size = dap_chain_datum_decree_get_size(a_decree);

    if ((ret_val = dap_ledger_decree_verify(a_ledger, a_decree, l_data_size, a_decree_hash)) != 0) {
        //log_it(L_ERROR, "Decree verification failed!");
        return ret_val;
    }

    return dap_ledger_decree_apply(a_ledger, a_decree_hash, a_decree, a_chain_id, NULL);
}

int dap_ledger_decree_reset_applied(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_decree_hash)
{
    dap_return_val_if_fail(a_ledger && a_decree_hash, -1);
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_sought_decree = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    if (!l_sought_decree)
        return -2;
    l_sought_decree->is_applied = false;
    return 0;
}

dap_chain_datum_decree_t *dap_ledger_decree_get_by_hash(dap_ledger_t *a_ledger, dap_hash_fast_t *a_decree_hash, bool *is_applied)
{
    dap_return_val_if_fail(a_ledger && a_decree_hash, NULL);
    dap_ledger_decree_item_t *l_sought_decree = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    return ( !l_sought_decree || !l_sought_decree->decree )
        ? NULL
        : ({ if (is_applied) { *is_applied = l_sought_decree->is_applied; } l_sought_decree->decree; });
}

// Private functions
static bool s_verify_pkey (dap_sign_t *a_sign, dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    for (dap_list_t *it = l_ledger_pvt->decree_owners_pkeys; it; it = it->next)
        if (dap_pkey_compare_with_sign(it->data, a_sign))
            return true;
    return false;
}

static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_ledger_t *a_ledger, bool a_apply, bool a_anchored)
{
    uint256_t l_value;
    uint64_t l_block_num;
    dap_chain_addr_t l_addr = {};
    dap_list_t *l_owners_list = NULL;

    dap_return_val_if_fail(a_decree && a_ledger, -112);

    for (dap_ledger_decree_callback_item_t *it = s_decree_callbacks; it; it = it->next) {
        if (it->type == a_decree->header.type && it->subtype == a_decree->header.sub_type) {
            return it->callback(a_ledger, a_decree, a_apply, a_anchored);
        }
    }

    switch (a_decree->header.sub_type)
    {
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD:
            // Reward decree - validate TSD structure but don't apply any changes
            // Actual reward processing is done by chain module when blocks are created
            if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
                log_it(L_WARNING, "Can't get reward value from decree");
                return -102;
            }
            if (IS_ZERO_256(l_value)) {
                log_it(L_WARNING, "Reward value is zero");
                return -114;
            }
            // Reward decree is valid, no further action needed
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
            if (!a_anchored)
                break;
            if (dap_chain_datum_decree_get_fee(a_decree, &l_value))
                return log_it(L_WARNING,"Can't get fee value from decree"), -103;
            if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
                // If no fee address in decree, use current ledger's fee address
                l_addr = a_ledger->fee_addr;
                if (dap_chain_addr_is_blank(&l_addr))
                    return log_it(L_WARNING, "Fee wallet address not set"), -111;
            }
            if (!a_apply)
                break;
            // Call fee set callback registered by net module
            if (a_ledger->decree_set_fee_callback) {
                int ret = a_ledger->decree_set_fee_callback(a_ledger, l_value, l_addr);
                if (ret != 0) {
                    log_it(L_ERROR, "Failed to set fee via callback, error %d", ret);
                    return ret;
                }
            } else {
                log_it(L_WARNING, "No decree_set_fee_callback registered");
            }
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            l_owners_list = dap_chain_datum_decree_get_owners(a_decree, NULL);
            if (!l_owners_list){
                log_it(L_WARNING,"Can't get ownners from decree.");
                return -104;
            }
            if (!a_apply)
                break;
            dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
            l_ledger_pvt->decree_num_of_owners = dap_list_length(l_owners_list);
            dap_list_free_full(l_ledger_pvt->decree_owners_pkeys, NULL);
            l_ledger_pvt->decree_owners_pkeys = l_owners_list;
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
            if (dap_chain_datum_decree_get_min_owners(a_decree, &l_value)) {
                log_it(L_WARNING, "Can't get min number of ownners from decree.");
                return -105;
            }
            if (IS_ZERO_256(l_value) || compare256(l_value, GET_256_FROM_64(UINT16_MAX)) == 1) {
                log_it(L_WARNING, "Illegal min number of owners %s", dap_uint256_to_char(l_value, NULL));
                return -116;
            }
            if (!a_apply)
                break;
            PVT(a_ledger)->decree_min_num_of_signers = dap_uint256_to_uint64(l_value);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_CANCEL:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_ADD:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_REMOVE:
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMPTY_BLOCKGEN: {
            // Complex decree types - delegate to generic callback registered by net/consensus module
            if (a_ledger->decree_generic_callback) {
                dap_chain_id_t l_chain_id = a_decree->header.common_decree_params.chain_id;
                return a_ledger->decree_generic_callback(a_ledger, a_decree, l_chain_id, a_apply, a_anchored);
            } else {
                log_it(L_WARNING, "No generic decree callback registered for subtype %u", a_decree->header.sub_type);
                return -1;
            }
        }
        default:
            return -1;
    }

    return 0;
}

static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_ledger_t *a_ledger, bool a_apply)
{
    // SERVICE decree is handled through event mechanism (DAP_CHAIN_TX_EVENT_TYPE_SERVICE_DECREE)
    // See dap_chain_ledger_event.c:278-286 for actual implementation
    return 0;
}

uint16_t dap_ledger_decree_get_min_num_of_signers(dap_ledger_t *a_ledger)
{
    return PVT(a_ledger)->decree_min_num_of_signers;
}

uint16_t dap_ledger_decree_get_num_of_owners(dap_ledger_t *a_ledger)
{
    return PVT(a_ledger)->decree_num_of_owners;
}

const dap_list_t *dap_ledger_decree_get_owners_pkeys(dap_ledger_t *a_ledger)
{
    return PVT(a_ledger)->decree_owners_pkeys;
}

static bool s_compare_anchors(dap_ledger_t *a_ledger, dap_ledger_hardfork_anchors_t *a_exist, dap_ledger_hardfork_anchors_t *a_comp)
{
    bool l_stake_type = false, l_ban_type = false;
    switch (a_comp->decree_subtype) {
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE:
        if (a_exist->decree_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE &&
                a_exist->decree_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE)
            return false;
        l_stake_type = true;
        break;
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN:
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN:
        if (a_exist->decree_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN &&
                a_exist->decree_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN)
            return false;
        l_ban_type = true;
        break;
    default:
        return a_exist->decree_subtype == a_comp->decree_subtype;
    }
    dap_hash_fast_t l_exist_hash = {}, l_comp_hash = {};
    dap_chain_datum_anchor_get_hash_from_data(a_comp->anchor, &l_comp_hash);
    dap_chain_datum_anchor_get_hash_from_data(a_exist->anchor, &l_exist_hash);
    dap_chain_datum_decree_t *l_comp_decree = dap_ledger_decree_get_by_hash(a_ledger, &l_comp_hash, NULL);
    dap_chain_datum_decree_t *l_exist_decree = dap_ledger_decree_get_by_hash(a_ledger, &l_exist_hash, NULL);
    if (l_ban_type) {
        const char *l_comp_ban_addr = NULL, *l_exist_ban_addr = NULL;
        dap_chain_datum_decree_get_ban_addr(l_comp_decree, &l_comp_ban_addr);
        dap_chain_datum_decree_get_ban_addr(l_exist_decree, &l_exist_ban_addr);
        if (!dap_strcmp(l_comp_ban_addr, l_exist_ban_addr))
            return true;
        return false;
    }
    if (l_stake_type) {
        dap_chain_addr_t l_comp_addr = {}, l_exist_addr = {};
        dap_chain_datum_decree_get_stake_signing_addr(l_comp_decree, &l_comp_addr);
        dap_chain_datum_decree_get_stake_signing_addr(l_exist_decree, &l_exist_addr);
        if (!dap_chain_addr_is_blank(&l_comp_addr) && dap_chain_addr_compare(&l_comp_addr, &l_exist_addr))
            return true;
        return false;
    }
    return assert(false), false;
}


int s_aggregate_anchor(dap_ledger_t *a_ledger, dap_ledger_hardfork_anchors_t **a_out_list, uint16_t a_subtype, dap_chain_datum_anchor_t *a_anchor)
{
    dap_ledger_hardfork_anchors_t l_new_anchor = {
            .anchor = DAP_DUP_SIZE(a_anchor, dap_chain_datum_anchor_get_size(a_anchor)),
            .decree_subtype = a_subtype
    };
    dap_ledger_hardfork_anchors_t *l_exist = NULL, *l_tmp;
    DL_FOREACH_SAFE(*a_out_list, l_exist, l_tmp)
        if (s_compare_anchors(a_ledger, l_exist, &l_new_anchor))
            break;
    if (!l_exist) {
        l_exist = DAP_DUP(&l_new_anchor);
        if (!l_exist) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        if (a_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE &&      // Do not aagregate stake anchors, it will be transferred with
                a_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE &&     // hardfork decree data linked to genesis block
                a_subtype != DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN)
            DL_APPEND(*a_out_list, l_exist);
    } else {
        if (l_exist->decree_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN) {
            assert(a_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN);
            DL_DELETE(*a_out_list, l_exist);
        } else {
            DAP_DEL_Z(l_exist->anchor);
            l_exist->anchor = DAP_DUP_SIZE(a_anchor, dap_chain_datum_anchor_get_size(a_anchor));
        }
    }
    return 0;
}

dap_ledger_hardfork_anchors_t *dap_ledger_anchors_aggregate(dap_ledger_t *a_ledger, dap_chain_id_t a_chain_id)
{
    dap_ledger_hardfork_anchors_t *ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    for (dap_ledger_decree_item_t *it = l_ledger_pvt->decrees; it; it = it->hh.next) {
        if (!it->is_applied)
            continue;
        if (it->decree->header.common_decree_params.chain_id.uint64 != a_chain_id.uint64)
            continue;
        if (dap_hash_fast_is_blank(&it->anchor_hash))
            continue;
        if (it->decree->header.sub_type == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK ||
                it->decree->header.sub_type == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE ||
                it->decree->header.sub_type == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY)
            continue;
        dap_chain_datum_anchor_t *l_anchor = dap_ledger_anchor_find(a_ledger, &it->anchor_hash);
        if (!l_anchor) {
            char l_anchor_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&it->anchor_hash, l_anchor_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_ERROR, "Can't find anchor %s for decree %s, skip it",
                                        l_anchor_hash_str, dap_hash_fast_to_str_static(&it->decree_hash));
            continue;
        }
        dap_hash_fast_t l_decree_hash;
        if (dap_chain_datum_anchor_get_hash_from_data(l_anchor, &l_decree_hash)) {
            log_it(L_ERROR, "Corrupted datum anchor %s, can't get decree hash from it", dap_hash_fast_to_str_static(&it->anchor_hash));
            continue;
        }
        s_aggregate_anchor(a_ledger, &ret, it->decree->header.sub_type, l_anchor);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    return ret;
}

/**
 * @brief get tsd list with decrees hashes in concretyc type
 * @param a_ledger ledger to search
 * @param a_type - searching type, if 0 - all hashes
 * @return if OK - ponter tsd list, if error - NULL
 */
dap_list_t *dap_ledger_decrees_get_by_type(dap_ledger_t *a_ledger, int a_type)
{
    dap_return_val_if_pass(!a_ledger, NULL);
    dap_list_t *l_ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_cur_decree, *l_tmp;
    pthread_rwlock_wrlock(&l_ledger_pvt->decrees_rwlock);
    HASH_ITER(hh, l_ledger_pvt->decrees, l_cur_decree, l_tmp) {
        if (!a_type || (l_cur_decree->decree && l_cur_decree->decree->header.type == a_type)) {
            dap_tsd_t *l_tsd_cur = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH, &l_cur_decree->decree_hash, sizeof(l_cur_decree->decree_hash));
            l_ret = dap_list_append(l_ret, l_tsd_cur);
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    return l_ret;
}
