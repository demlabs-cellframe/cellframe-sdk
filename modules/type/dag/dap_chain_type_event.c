/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include "dap_chain_type_dag_event.h"
#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_chain_datum.h"
#include "dap_chain_type_dag.h"
#include "dap_timerfd.h"

#define LOG_TAG "dap_chain_type_dag_event"

/**
 * @brief dap_chain_type_dag_event_new
 * @param a_chain_id
 * @param a_cell_id
 * @param a_datum
 * @param a_key
 * @param a_hashes
 * @param a_hashes_count
 * @return
 */
dap_chain_type_dag_event_t *dap_chain_type_dag_event_new(dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                                     dap_chain_datum_t *a_datum, dap_enc_key_t *a_key, dap_chain_hash_fast_t *a_hashes,
                                                     size_t a_hashes_count, size_t *a_event_size)
{
    assert(a_event_size);
    size_t l_hashes_size = sizeof(*a_hashes) * a_hashes_count,
        l_datum_size = dap_chain_datum_size(a_datum),
        l_event_size = sizeof(dap_chain_class_dag_event_hdr_t) + l_hashes_size + l_datum_size;
    dap_chain_type_dag_event_t *l_event_new = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_type_dag_event_t, l_event_size, NULL);
    *l_event_new = (dap_chain_type_dag_event_t) {
        {
            .ts_created = dap_time_now(),
            .chain_id = a_chain_id,
            .cell_id = a_cell_id,
            .hash_count = a_hashes_count
        }
    };

    if ( l_hashes_size )
        memcpy( l_event_new->hashes_n_datum_n_signs, a_hashes, l_hashes_size );
    memcpy( l_event_new->hashes_n_datum_n_signs + l_hashes_size, a_datum,l_datum_size );

    if ( a_key ){
        dap_sign_t *l_sign = dap_sign_create(a_key, l_event_new, l_event_size);
        if ( !l_sign )
            return DAP_DELETE(l_event_new), log_it(L_ERROR,"Can't sign dag event!"), NULL;
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_event_size += l_sign_size;
        dap_chain_type_dag_event_t *l_event_newer
            = DAP_REALLOC_RET_VAL_IF_FAIL(l_event_new, l_event_size, NULL, l_event_new, l_sign);
        l_event_new = l_event_newer;
        memcpy(l_event_new->hashes_n_datum_n_signs + l_hashes_size + l_datum_size, l_sign, l_sign_size);
        ++l_event_new->header.signs_count;
        log_it(L_INFO,"Created event size %zd, signed with sign size %zd", l_event_size, l_sign_size);
        DAP_DELETE(l_sign);
    } else {
        log_it(L_NOTICE, "Created unsigned dag event");
    }
    if (a_event_size)
        *a_event_size = l_event_size;
    return l_event_new;
}

/**
 * @brief dap_chain_type_dag_event_calc_size_excl_signs
 * @param a_event
 * @return
 */
uint64_t dap_chain_type_dag_event_calc_size_excl_signs(dap_chain_type_dag_event_t *a_event, uint64_t a_limit_size)
{
    dap_return_val_if_fail(a_event, 0);
    if (a_limit_size && a_limit_size < sizeof(a_event->header))
        return 0;
    uint32_t l_hashes_size = a_event->header.hash_count * sizeof(dap_chain_hash_fast_t);
    if (a_limit_size && a_limit_size < l_hashes_size + sizeof(a_event->header) + sizeof(dap_chain_datum_t))
        return 0;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)(a_event->hashes_n_datum_n_signs + l_hashes_size);
    uint64_t l_ret = dap_chain_datum_size(l_datum) + l_hashes_size + sizeof(a_event->header);
    return a_limit_size && a_limit_size < l_ret ? 0 : l_ret;
}

/**
 * @brief dap_chain_type_dag_event_calc_size
 * @param a_event
 * @return
 */
uint64_t dap_chain_type_dag_event_calc_size(dap_chain_type_dag_event_t *a_event, uint64_t a_limit_size)
{
    dap_return_val_if_fail(a_event, 0);
    uint64_t l_signs_offset = dap_chain_type_dag_event_calc_size_excl_signs(a_event, a_limit_size);
    if (!l_signs_offset)
        return 0;
    byte_t *l_signs = (byte_t *)a_event + l_signs_offset;
    size_t l_signs_size = 0;
    for (uint16_t l_signs_passed = 0; l_signs_passed < a_event->header.signs_count; l_signs_passed++) {
        dap_sign_t *l_sign = (dap_sign_t *)(l_signs + l_signs_size);
        if (l_signs_offset + l_signs_size + sizeof(dap_sign_t) <= l_signs_offset)
            return 0;
        if (a_limit_size && a_limit_size < l_signs_offset + l_signs_size + sizeof(dap_sign_t))
            return 0;
        uint64_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size)
            break;
        if (l_signs_size + l_sign_size <= l_signs_size)
            return 0;
        l_signs_size += l_sign_size;
    }
    size_t l_total_size = l_signs_offset + l_signs_size <= l_signs_offset ? 0 : l_signs_offset + l_signs_size;
    return a_limit_size && l_total_size > a_limit_size ? 0 : l_total_size;
}

/**
 * @brief dap_chain_type_dag_event_sign_add
 * @param a_event
 * @param l_key
 * @return
 */
size_t dap_chain_type_dag_event_sign_add(dap_chain_type_dag_event_t **a_event_ptr, size_t a_event_size, dap_enc_key_t * a_key)
{
    assert(a_event_ptr);
    dap_chain_type_dag_event_t *l_event = *a_event_ptr;
    // check for re-sign with same key
    if (dap_chain_type_dag_event_sign_exists(l_event, a_event_size, a_key)) {
        size_t l_pub_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_size);
        return log_it(L_DEBUG, "Already signed with pkey %s", dap_get_data_hash_str(l_pub_key, l_pub_key_size).s), DAP_DELETE(l_pub_key), 0;
    }
    size_t l_event_size_excl_sign = dap_chain_type_dag_event_calc_size_excl_signs(l_event, a_event_size);
    dap_sign_t *l_sign = dap_sign_create(a_key, l_event, l_event_size_excl_sign);
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_event = DAP_REALLOC_RET_VAL_IF_FAIL(*a_event_ptr, a_event_size + l_sign_size, a_event_size, l_sign);
    size_t l_event_size = a_event_size - sizeof(l_event->header);
    memcpy(l_event->hashes_n_datum_n_signs + l_event_size, l_sign, l_sign_size);
    ++l_event->header.signs_count;
    DAP_DELETE(l_sign);
    *a_event_ptr = l_event;
    return a_event_size + l_sign_size;
}

static bool s_sign_exists(uint8_t *a_pos, size_t a_len, dap_enc_key_t *a_key)
{
    size_t l_pub_key_size = 0;
    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_size);
    uint8_t *l_offset = a_pos;
    while (l_offset < a_pos + a_len) {
        dap_sign_t * l_item_sign = (dap_sign_t *)l_offset;
        size_t l_sign_item_size = dap_sign_get_size(l_item_sign);
        size_t l_sign_key_size = 0;
        uint8_t *l_sign_key = dap_sign_get_pkey(l_item_sign, &l_sign_key_size);
        if (l_pub_key_size == l_sign_key_size &&
                !memcmp(l_pub_key, l_sign_key, l_pub_key_size)) {
            DAP_DELETE(l_pub_key);
            return true;
        }
        l_offset += l_sign_item_size;
    }
    assert(l_offset == a_pos + a_len);
    DAP_DELETE(l_pub_key);
    return false;
}

bool dap_chain_type_dag_event_sign_exists(dap_chain_type_dag_event_t *a_event, size_t a_event_size, dap_enc_key_t *a_key)
{
    size_t l_hashes_size = a_event->header.hash_count * sizeof(dap_chain_hash_fast_t);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)(a_event->hashes_n_datum_n_signs + l_hashes_size);
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    return s_sign_exists(a_event->hashes_n_datum_n_signs + l_hashes_size + l_datum_size,
                        a_event_size - sizeof(a_event->header) - l_hashes_size - l_datum_size,
                        a_key);
}

bool dap_chain_type_dag_event_round_sign_exists(dap_chain_type_dag_event_round_item_t *a_round_item, dap_enc_key_t *a_key) {
    return s_sign_exists(a_round_item->event_n_signs + a_round_item->event_size,
                        (size_t)(a_round_item->data_size - a_round_item->event_size),
                        a_key); 
}

/**
 * @brief dap_chain_type_dag_event_get_sign
 * @param a_event
 * @param a_sign_number
 * @return
 */
dap_sign_t * dap_chain_type_dag_event_get_sign( dap_chain_type_dag_event_t * a_event, size_t a_event_size, uint16_t a_sign_number)
{
    size_t l_offset_passed = sizeof (a_event->header);
    if (a_event->header.signs_count > a_sign_number ){
        size_t l_offset_to_sign = dap_chain_type_dag_event_calc_size_excl_signs(a_event,a_event_size);
        l_offset_passed += l_offset_to_sign;
        if ( l_offset_passed >= a_event_size)
            return NULL;
        uint8_t * l_signs = ((uint8_t*) a_event)+l_offset_to_sign;
        uint16_t l_signs_offset = 0;
        uint16_t l_signs_passed;
        for ( l_signs_passed=0;  l_signs_passed < a_sign_number; l_signs_passed++){
            dap_sign_t * l_sign = (dap_sign_t *) (l_signs+l_signs_offset);
            // l_signs_offset+=l_sign->header.sign_pkey_size+l_sign->header.sign_size+sizeof(l_sign->header);
            l_signs_offset+=dap_sign_get_size(l_sign);
            l_offset_passed += l_offset_to_sign;
            if ( l_offset_passed >= a_event_size)
                return NULL;
        }
        return (dap_sign_t*)(l_signs+l_signs_offset);
    }else
        return NULL;
}

size_t dap_chain_type_dag_event_round_sign_add(dap_chain_type_dag_event_round_item_t **a_round_item_ptr, size_t a_round_item_size, dap_enc_key_t *a_key)
{
    dap_chain_type_dag_event_round_item_t *l_round_item = *a_round_item_ptr;
    if (dap_chain_type_dag_event_round_sign_exists(l_round_item, a_key))
        return 0;
    dap_sign_t * l_sign = dap_sign_create(a_key, &l_round_item->round_info.datum_hash, sizeof(dap_chain_hash_fast_t));
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_round_item = DAP_REALLOC_RET_VAL_IF_FAIL(*a_round_item_ptr, a_round_item_size + l_sign_size, a_round_item_size, l_sign);
    *a_round_item_ptr = l_round_item;
    memcpy(l_round_item->event_n_signs + l_round_item->data_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    return l_round_item->data_size += (uint32_t)l_sign_size;
}

/**
 * @brief dap_chain_type_dag_event_gdb_set
 * @param a_dag
 * @param a_event_hash_str
 * @param a_event
 * @param a_event_size
 * @param a_round_item
 * @param a_group
 * @return
 */
bool dap_chain_type_dag_event_gdb_set(dap_chain_type_dag_t *a_dag, const char *a_event_hash_str, dap_chain_type_dag_event_t *a_event,
                                    size_t a_event_size, dap_chain_type_dag_event_round_item_t *a_round_item)
{
    size_t l_signs_size = (size_t)(a_round_item->data_size-a_round_item->event_size);
    uint8_t *l_signs = (uint8_t*)a_round_item->event_n_signs + (size_t)a_round_item->event_size;
    dap_chain_type_dag_event_round_item_t * l_round_item
            = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_type_dag_event_round_item_t,
                           sizeof(dap_chain_type_dag_event_round_item_t) + a_event_size + l_signs_size, false);

    l_round_item->event_size = (uint32_t)a_event_size;
    l_round_item->data_size = (uint32_t)(a_event_size+l_signs_size);
    l_round_item->round_info = a_round_item->round_info;

    memcpy(l_round_item->event_n_signs,                 a_event, a_event_size);
    memcpy(l_round_item->event_n_signs + a_event_size,  l_signs, l_signs_size);

    l_round_item->round_info.ts_update = dap_nanotime_now();

    size_t l_round_item_size = dap_chain_type_dag_event_round_item_get_size(l_round_item);
    bool ret = dap_global_db_set(a_dag->gdb_group_events_round_new, a_event_hash_str, l_round_item,
                                 l_round_item_size, false, NULL, NULL) == DAP_GLOBAL_DB_RC_SUCCESS;
    DAP_DELETE(l_round_item);
    return ret;
}

dap_chain_type_dag_event_t* dap_chain_type_dag_event_gdb_get(const char *a_event_hash_str, size_t *a_event_size, const char *a_group,
                                                            dap_chain_type_dag_event_round_info_t * a_event_round_info) {
    size_t l_event_round_item_size = 0;
    dap_chain_type_dag_event_round_item_t* l_event_round_item =
                (dap_chain_type_dag_event_round_item_t*)dap_global_db_get_sync(a_group, a_event_hash_str, &l_event_round_item_size, NULL, NULL);
    if ( !l_event_round_item )
        return NULL;
    size_t l_event_size = (size_t)l_event_round_item->event_size;
    dap_chain_type_dag_event_t* l_event = DAP_DUP_SIZE_RET_VAL_IF_FAIL((dap_chain_type_dag_event_t*)l_event_round_item->event_n_signs, l_event_round_item->event_size, NULL, l_event_round_item);
    *a_event_round_info = l_event_round_item->round_info;
    *a_event_size = l_event_size;
    return DAP_DELETE(l_event_round_item), l_event;
}

