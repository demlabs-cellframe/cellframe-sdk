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
#include "dap_chain_datum_tx_tsd.h"
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_pkey.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_http_ban_list_client.h"
#include "dap_chain_policy.h"
#include "dap_json.h"
#include "dap_chain_srv.h"

#define LOG_TAG "dap_ledger_decree"

// Private fuctions prototype
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net);
static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply, bool a_anchored);
static int s_service_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply);

// Public functions

void dap_ledger_decree_init(dap_ledger_t *a_ledger) {
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    l_ledger_pvt->decree_min_num_of_signers = a_ledger->net->pub.keys_min_count;
    l_ledger_pvt->decree_num_of_owners = dap_list_length(a_ledger->net->pub.keys);
    l_ledger_pvt->decree_owners_pkeys = a_ledger->net->pub.keys;
    if ( !l_ledger_pvt->decree_owners_pkeys )
        log_it(L_WARNING, "PoA certificates for net %s not found", a_ledger->net->pub.name);
}

static int s_decree_clear(dap_ledger_t *a_ledger, dap_chain_id_t a_chain_id)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_decree_item_t *l_cur_decree, *l_tmp;
    pthread_rwlock_wrlock(&l_ledger_pvt->decrees_rwlock);
    dap_chain_policy_net_purge(a_ledger->net->pub.id);
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

int dap_ledger_decree_purge(dap_ledger_t *a_ledger)
{
    dap_return_val_if_fail(a_ledger, -1);
    int ret = 0;
    for (dap_chain_t *l_chain = a_ledger->net->pub.chains; l_chain; l_chain = l_chain->next) {
        if (dap_chain_datum_type_supported_by_chain(l_chain, DAP_CHAIN_DATUM_DECREE)) {
            ret += s_decree_clear(a_ledger, l_chain->id);
            dap_list_free_full(PVT(a_ledger)->decree_owners_pkeys, NULL);
        } else
            ret += dap_ledger_anchor_purge(a_ledger, l_chain->id);
    }
    return ret;
}

static int s_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash, bool a_anchored)
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

    dap_ledger_private_t *l_ledger_pvt = PVT(a_net->pub.ledger);
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
    dap_chain_datum_decree_t *l_decree = a_net->pub.chains->is_mapped
        ? DAP_DUP_SIZE(a_decree, a_data_size)
        : a_decree;
    l_decree->header.signs_size = 0;
    size_t l_verify_data_size = l_decree->header.data_size + sizeof(dap_chain_datum_decree_t);

    for (size_t i = 0; i < l_num_of_unique_signs; i++) {
        size_t l_sign_max_size = dap_sign_get_size(l_unique_signs[i]);
        if (s_verify_pkey(l_unique_signs[i], a_net)) {
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

    if ( a_net->pub.chains->is_mapped )
        DAP_DELETE(l_decree);
    else
        l_decree->header.signs_size = l_signs_size;
    DAP_DELETE(l_unique_signs);

    if (l_signs_verify_counter < l_min_signs) {
        log_it(L_WARNING, "Not enough valid signatures, get %hu from %hu", l_signs_verify_counter, l_min_signs);
        return -107;
    }

    // check tsd-section
    int l_ret = 0;
    switch(a_decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        l_ret = s_common_decree_handler(a_decree, a_net, false, a_anchored);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        l_ret = s_service_decree_handler(a_decree, a_net, false);
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

int dap_ledger_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash)
{
    return s_decree_verify(a_net, a_decree, a_data_size, a_decree_hash, false);
}

int dap_ledger_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash)
{
    dap_return_val_if_fail(a_decree_hash && a_chain, -107);
    int ret_val = 0;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    
    if (!l_net) {
        log_it(L_WARNING, "Invalid net ID 0x%016" DAP_UINT64_FORMAT_x, a_chain->net_id.uint64);
        return -108;
    }
    dap_ledger_private_t *l_ledger_pvt = PVT(l_net->pub.ledger);
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
        l_new_decree->storage_chain_id = a_chain->id;
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
        l_new_decree->decree = a_chain->is_mapped ? a_decree : DAP_DUP_SIZE(a_decree, dap_chain_datum_decree_get_size(a_decree));
        if (a_decree->header.common_decree_params.chain_id.uint64 != a_chain->id.uint64 && !l_new_decree->wait_for_apply)
            // Apply it with corresponding anchor
            return ret_val;
    }

    // Process decree
    switch(l_new_decree->decree->header.type) {
    case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
        ret_val = s_common_decree_handler(l_new_decree->decree, l_net, true, a_anchor_hash);
        break;
    case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
        ret_val = s_service_decree_handler(l_new_decree->decree, l_net, true);
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

int dap_ledger_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash)
{
    int ret_val = 0;
    if (!a_chain || !a_decree) {
        log_it(L_ERROR, "Bad arguments");
        return -100;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    size_t l_data_size = dap_chain_datum_decree_get_size(a_decree);

    if ((ret_val = s_decree_verify(l_net, a_decree, l_data_size, a_decree_hash, false)) != 0) {
        //log_it(L_ERROR, "Decree verification failed!");
        return ret_val;
    }

    return dap_ledger_decree_apply(a_decree_hash, a_decree, a_chain, NULL);
}

int dap_ledger_decree_reset_applied(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_decree_hash)
{
    dap_return_val_if_fail(a_net && a_decree_hash, -1);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_net->pub.ledger);
    dap_ledger_decree_item_t *l_sought_decree = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    if (!l_sought_decree)
        return -2;
    l_sought_decree->is_applied = false;
    return 0;
}

dap_chain_datum_decree_t *dap_ledger_decree_get_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_decree_hash, bool *is_applied)
{
    dap_return_val_if_fail(a_net && a_decree_hash, NULL);
    dap_ledger_decree_item_t *l_sought_decree = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_net->pub.ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->decrees_rwlock);
    HASH_FIND(hh, l_ledger_pvt->decrees, a_decree_hash, sizeof(dap_hash_fast_t), l_sought_decree);
    pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock);
    return ( !l_sought_decree || !l_sought_decree->decree )
        ? NULL
        : ({ if (is_applied) { *is_applied = l_sought_decree->is_applied; } l_sought_decree->decree; });
}

// Private functions
static bool s_verify_pkey (dap_sign_t *a_sign, dap_chain_net_t *a_net)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_net->pub.ledger);
    for (dap_list_t *it = l_ledger_pvt->decree_owners_pkeys; it; it = it->next)
        if (dap_pkey_compare_with_sign(it->data, a_sign))
            return true;
    return false;
}

static int s_common_decree_handler(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net, bool a_apply, bool a_anchored)
{
uint256_t l_value;
uint64_t l_block_num;
uint32_t l_sign_type;
uint16_t l_owners_num;
uint8_t l_action;
dap_chain_addr_t l_addr = {};
dap_hash_fast_t l_hash = {};
dap_chain_node_addr_t l_node_addr = {};
dap_list_t *l_owners_list = NULL;
const char *l_ban_addr;

    dap_return_val_if_fail(a_decree && a_net, -112);

    switch (a_decree->header.sub_type)
    {
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
            /* if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
                if (dap_chain_addr_is_blank(&a_net->pub.fee_addr)) {
                    log_it(L_WARNING, "Fee wallet address not set.");
                    return -111;
                } else
                    l_addr = a_net->pub.fee_addr;
            } */
            if (!a_anchored)
                break;
            if (dap_chain_datum_decree_get_fee(a_decree, &l_value))
                return log_it(L_WARNING,"Can't get fee value from decree"), -103;
            if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
                if (dap_chain_addr_is_blank(&a_net->pub.fee_addr))
                    return log_it(L_WARNING, "Fee wallet address not set"), -111;
                else
                    l_addr = a_net->pub.fee_addr;
            }
            if (!a_apply)
                break;
            if (!dap_chain_net_tx_set_fee(a_net->pub.id, l_value, l_addr))
                log_it(L_ERROR, "Can't set fee value for network %s", a_net->pub.name);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
            l_owners_list = dap_chain_datum_decree_get_owners(a_decree, &l_owners_num);
            if (!l_owners_list){
                log_it(L_WARNING,"Can't get ownners from decree.");
                return -104;
            }
            if (!a_apply)
                break;
            dap_ledger_private_t *l_ledger_pvt = PVT(a_net->pub.ledger);
            l_ledger_pvt->decree_num_of_owners = l_owners_num;
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
            PVT(a_net->pub.ledger)->decree_min_num_of_signers = dap_uint256_to_uint64(l_value);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:
            if (dap_chain_datum_decree_get_hash(a_decree, &l_hash)){
                log_it(L_WARNING,"Can't get tx hash from decree.");
                return -105;
            }
            if (dap_chain_datum_decree_get_stake_value(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get stake value from decree.");
                return -106;
            }
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -107;
            }
            if (dap_chain_datum_decree_get_node_addr(a_decree, &l_node_addr)){
                log_it(L_WARNING,"Can't get signer node address from decree.");
                return -108;
            }
            if (!a_anchored)
                break;
            if (dap_chain_net_srv_stake_verify_key_and_node(&l_addr, &l_node_addr)) {
                debug_if(g_debug_ledger, L_WARNING, "Key and node verification error");
                return -109;
            }
            if (!a_apply)
                break;
            
            dap_chain_net_srv_stake_key_delegate(a_net, &l_addr, a_decree, l_value, &l_node_addr, dap_chain_datum_decree_get_pkey(a_decree));
            if (!dap_chain_net_get_load_mode(a_net))
                dap_chain_net_srv_stake_add_approving_decree_info(a_decree, a_net);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE:
            if (!a_anchored)
                break;
            if (!a_apply)
                break;
            dap_pkey_t *l_pkey = NULL;
            if (! (l_pkey = dap_chain_datum_decree_get_pkey(a_decree)) ){
                log_it(L_WARNING,"Can't get pkey from decree.");
                return -105;
            }
            dap_chain_net_srv_stake_pkey_update(a_net, l_pkey);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE: {
            if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
                log_it(L_WARNING,"Can't get signing address from decree.");
                return -105;
            }
            if (!a_anchored)
                break;
            uint16_t l_min_count = dap_chain_esbocs_get_min_validators_count(a_net->pub.id);
            if ( dap_chain_net_srv_stake_get_total_keys(a_net->pub.id, NULL) == l_min_count ) {
                log_it(L_WARNING, "Can't invalidate stake in net %s: results in minimum validators count %hu underflow",
                                   a_net->pub.name, l_min_count);
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_remove_approving_decree_info(a_net, &l_addr);
            dap_chain_net_srv_stake_key_invalidate(&l_addr);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE:
            if (dap_chain_datum_decree_get_stake_min_value(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_set_allowed_min_value(a_net->pub.id, l_value);
            break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT: {
            if (dap_chain_datum_decree_get_stake_min_signers_count(a_decree, &l_value)){
                log_it(L_WARNING,"Can't get min stake value from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_anchored)
                break;
            uint16_t l_decree_count = (uint16_t)dap_chain_uint256_to(l_value);
            uint16_t l_current_count = dap_chain_net_srv_stake_get_total_keys(a_net->pub.id, NULL);
            if (l_decree_count > l_current_count) {
                log_it(L_WARNING, "Minimum validators count by decree %hu is greater than total validators count %hu in network %s",
                                                                            l_decree_count, l_current_count, a_net->pub.name);
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_esbocs_set_min_validators_count(l_chain, l_decree_count);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN: {
            if (dap_chain_datum_decree_get_ban_addr(a_decree, &l_ban_addr)) {
                log_it(L_WARNING, "Can't get ban address from decree.");
                return -114;
            }
            if (dap_http_ban_list_client_check(l_ban_addr, NULL, NULL)) {
                log_it(L_ERROR, "Can't ban addr %s: already banlisted", l_ban_addr);
                return -112;
            }
            if (!a_apply)
                break;
            dap_hash_fast_t l_decree_hash = {0};
            dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
            dap_http_ban_list_client_add(l_ban_addr, l_decree_hash, a_decree->header.ts_created);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN: {
            if (dap_chain_datum_decree_get_ban_addr(a_decree, &l_ban_addr)) {
                log_it(L_WARNING, "Can't get ban address from decree.");
                return -114;
            }
            if (!dap_http_ban_list_client_check(l_ban_addr, NULL, NULL)) {
                log_it(L_ERROR, "Can't ban addr %s: already banlisted", l_ban_addr);
                return -112;
            }
            if (!a_apply)
                break;
            dap_http_ban_list_client_remove(l_ban_addr);
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD: {
            if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
                log_it(L_WARNING,"Can't get value from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            uint64_t l_cur_block_num = l_chain->callback_count_atom(l_chain);
            return dap_chain_net_add_reward(a_net, l_value, l_cur_block_num);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT: {
            if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
                log_it(L_WARNING,"Can't get value from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (compare256(l_value, dap_chain_balance_coins_scan("1.0")) >= 0) {
                log_it(L_WARNING, "Percent must be lower than 100%%");
                return -116;
            }
            if (!a_apply)
                break;
            dap_chain_net_srv_stake_set_percent_max(a_net->pub.id, l_value);
            return 0;
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE: {
            if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
                log_it(L_WARNING, "Can't get action from decree.");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            return dap_chain_esbocs_set_signs_struct_check(l_chain, l_action);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS: {
            if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
                log_it(L_WARNING,"Can't get action from decree.");
                return -103;
            }
            if (dap_chain_datum_decree_get_signature_type(a_decree, &l_sign_type)) {
                log_it(L_WARNING,"Can't get signature type from decree.");
                return -113;
            }
            if (dap_chain_datum_decree_get_hash(a_decree, &l_hash)){
                log_it(L_WARNING,"Can't get validator hash from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            return dap_chain_esbocs_set_emergency_validator(l_chain, l_action, l_sign_type, &l_hash);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK: {
            if (dap_chain_datum_decree_get_atom_num(a_decree, &l_block_num)) {
                log_it(L_WARNING, "Can't get atom number from hardfork prepare decree");
                return -103;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            dap_tsd_t *l_generation = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION);
            if (!l_generation || l_generation->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Can't apply this decree, it have no chain generation set");
                return -116;
            }
            uint16_t l_hardfork_generation = *(uint16_t *)l_generation->data;
            if (l_hardfork_generation <= l_chain->generation) {
                log_it(L_WARNING, "Invalid hardfork generation %hu, current generation is %hu", l_hardfork_generation, l_chain->generation);
                return -117;
            }

            if (!a_apply || (a_anchored && dap_chain_generation_banned(l_chain, l_hardfork_generation)))
                break;   // Silent hardfork start ignorance for banned generations

            dap_list_t *l_addrs = NULL, *l_addrs_tsd = dap_tsd_find_all(a_decree->data_n_signs, a_decree->header.data_size,
                                                   DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR, sizeof(dap_stream_node_addr_t));
            for (dap_list_t *it = l_addrs_tsd; it; it = it->next) {
                dap_tsd_t *l_tsd = (dap_tsd_t *)it->data;
                if (l_tsd->size != sizeof(dap_stream_node_addr_t)) {
                    dap_hash_fast_t l_decree_hash = {0};
                    dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
                    log_it(L_WARNING, "Invalid size of node addr tsd for decree %s", dap_hash_fast_to_str_static(&l_decree_hash));
                    continue;
                }
                dap_stream_node_addr_t *l_addr = (dap_stream_node_addr_t *)l_tsd->data;
                l_addrs = dap_list_append(l_addrs, DAP_DUP(l_addr));
            }
            dap_list_free_full(l_addrs_tsd, NULL);

            dap_tsd_t *l_changed_addrs = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS);
            dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_chain->hardfork_decree_hash);
            dap_json_tokener_error_t l_error;
            dap_json_t *l_changed_addrs_json = l_changed_addrs ? dap_json_tokener_parse_verbose((char *)l_changed_addrs->data, &l_error) : NULL;
            return dap_chain_esbocs_set_hardfork_prepare(l_chain, l_hardfork_generation, l_block_num, l_addrs, l_changed_addrs_json);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY: {
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!dap_chain_esbocs_hardfork_engaged(l_chain)) {
                log_it(L_WARNING, "Hardfork is not engaged, can't retry");
                return -116;
            }
            if (!a_apply)
                break;
            dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_chain->hardfork_decree_hash);
            return dap_chain_esbocs_set_hardfork_prepare(l_chain, 0, 0, NULL, NULL);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE: {
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            if (!a_apply)
                break;
            // Call hardfork complete callback for all registered services
            dap_chain_srv_hardfork_complete_all(a_net->pub.id);
            // Call hardfork complete for chain
            return dap_chain_esbocs_set_hardfork_complete(l_chain);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_CANCEL: {
            dap_tsd_t *l_chain_id = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CANCEL_CHAIN_ID);
            if (!l_chain_id || l_chain_id->size != sizeof(uint64_t)) {
                log_it(L_WARNING, "Can't apply this decree, it have no target chain ID set");
                return -116;
            }
            dap_chain_id_t l_target_chain_id = (dap_chain_id_t){ .uint64 = *(uint64_t *)l_chain_id->data };
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, l_target_chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            dap_tsd_t *l_generation = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION);
            if (!l_generation || l_generation->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Can't apply this decree, it have no chain generation set");
                return -116;
            }
            uint16_t l_banned_generation = *(uint16_t *)l_generation->data;
            if (!a_apply)
                break;
            if (l_chain->generation == l_banned_generation) {
                dap_chain_esbocs_set_hardfork_complete(l_chain);
                dap_ledger_chain_purge(l_chain, 0);
            }
            return dap_chain_generation_ban(l_chain, l_banned_generation);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY: {
            if (!a_apply)
                break;
            dap_chain_policy_t *l_policy = NULL;
            if ( !(l_policy = dap_chain_datum_decree_get_policy(a_decree)) ){
                log_it(L_WARNING,"Can't get policy from decree.");
                return -105;
            }
            return dap_chain_policy_apply(l_policy, a_net->pub.id);
        }
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_ADD: {
            dap_hash_fast_t l_pkey_hash;
            if (dap_chain_datum_decree_get_hash(a_decree, &l_pkey_hash)) {
                log_it(L_WARNING, "Can't get event pkey hash from decree.");
                return -114;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (!a_anchored)
                break;
            if (dap_ledger_event_pkey_check(a_net->pub.ledger, &l_pkey_hash)) {
                log_it(L_WARNING, "Event pkey already exists in ledger");
                return -116;
            }
            if (!a_apply)
                break;
            int l_ret = dap_ledger_event_pkey_add(a_net->pub.ledger, &l_pkey_hash);
            if (l_ret != 0) {
                log_it(l_ret == -2 ? L_INFO : L_ERROR, "Error adding event pkey to ledger: %d", l_ret);
                return -118;
            }
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_REMOVE: {
            dap_hash_fast_t l_pkey_hash;
            if (dap_chain_datum_decree_get_hash(a_decree, &l_pkey_hash)) {
                log_it(L_WARNING, "Can't get event pkey hash from decree.");
                return -114;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (!a_anchored)
                break;
            if (!dap_ledger_event_pkey_check(a_net->pub.ledger, &l_pkey_hash)) {
                log_it(L_WARNING, "Event pkey not found in ledger");
                return -116;
            }
            if (!a_apply)
                break;
            int l_ret = dap_ledger_event_pkey_rm(a_net->pub.ledger, &l_pkey_hash);
            if (l_ret != 0) {
                log_it(l_ret == -2 ? L_INFO : L_ERROR, "Error removing event pkey from ledger: %d", l_ret);
                return -118;
            }
        } break;
        case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMPTY_BLOCKGEN: {
            if (!a_apply)
                break;
            if (!a_anchored)
                break;
            uint16_t l_blockgen_period = 0;
            if (dap_chain_datum_decree_get_empty_block_every_times(a_decree, &l_blockgen_period)){
                log_it(L_WARNING,"Can't get empty blockgen period from decree.");
                return -105;
            }
            dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
            if (!l_chain) {
                log_it(L_WARNING, "Specified chain not found");
                return -106;
            }
            if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                log_it(L_WARNING, "Can't apply this decree to specified chain");
                return -115;
            }
            return dap_chain_esbocs_set_empty_block_every_times(l_chain, l_blockgen_period);
        }
        default:
            return -1;
    }

    return 0;
}

static int s_service_decree_handler(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net, bool a_apply)
{
   // size_t l_datum_data_size = ;
   //            dap_chain_srv_t * l_srv = dap_chain_srv_get(l_decree->header.srv_id);
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
    dap_chain_datum_decree_t *l_comp_decree = dap_ledger_decree_get_by_hash(a_ledger->net, &l_comp_hash, NULL);
    dap_chain_datum_decree_t *l_exist_decree = dap_ledger_decree_get_by_hash(a_ledger->net, &l_exist_hash, NULL);
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
