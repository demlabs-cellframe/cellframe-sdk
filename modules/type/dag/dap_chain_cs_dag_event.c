/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include "dap_chain_cs_dag_event.h"
#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs_dag.h"
#include "dap_timerfd.h"

#define LOG_TAG "dap_chain_cs_dag_event"

/**
 * @brief dap_chain_cs_dag_event_new
 * @param a_chain_id
 * @param a_cell_id
 * @param a_datum
 * @param a_key
 * @param a_hashes
 * @param a_hashes_count
 * @return
 */
dap_chain_cs_dag_event_t * dap_chain_cs_dag_event_new(dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, dap_chain_datum_t * a_datum,
                                                      dap_enc_key_t * a_key, dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count, size_t * a_event_size)
{
    assert(a_event_size);
    size_t l_hashes_size = sizeof(*a_hashes)*a_hashes_count;
    size_t l_datum_size =  dap_chain_datum_size(a_datum);
    dap_chain_cs_dag_event_t * l_event_new = NULL;
    size_t l_event_size = sizeof(l_event_new->header)
            + l_hashes_size
            + l_datum_size;
    l_event_new = DAP_NEW_Z_SIZE(dap_chain_cs_dag_event_t, l_event_size);
    l_event_new->header.ts_created = dap_time_now();
    l_event_new->header.cell_id.uint64 = a_cell_id.uint64;
    l_event_new->header.chain_id.uint64 = a_chain_id.uint64;
    l_event_new->header.hash_count = a_hashes_count;

    if ( l_hashes_size ){
        memcpy(l_event_new->hashes_n_datum_n_signs, a_hashes, l_hashes_size );
    }

    memcpy(l_event_new->hashes_n_datum_n_signs+l_hashes_size, a_datum,l_datum_size );

    if ( a_key ){
        dap_sign_t * l_sign = dap_sign_create(a_key, l_event_new, l_event_size, 0);
        if ( l_sign ){
            size_t l_sign_size = dap_sign_get_size(l_sign);
            l_event_size += l_sign_size;
            l_event_new = (dap_chain_cs_dag_event_t* )DAP_REALLOC(l_event_new, l_event_size);
            memcpy(l_event_new->hashes_n_datum_n_signs + l_hashes_size + l_datum_size, l_sign, l_sign_size);
            l_event_new->header.signs_count++;
            log_it(L_INFO,"Created event size %zd, signed with sign size %zd", l_event_size, l_sign_size);
            DAP_DELETE(l_sign);
        }else {
            log_it(L_ERROR,"Can't sign dag event!");
            DAP_DELETE(l_event_new);
            return NULL;
        }
    }else {
        log_it(L_NOTICE, "Created unsigned dag event");
    }
    if (a_event_size)
        *a_event_size = l_event_size;
    return l_event_new;
}

/**
 * @brief dap_chain_cs_dag_event_deep_copy
 * @param a_event_src
 * @return
 */
dap_chain_cs_dag_event_t * dap_chain_cs_dag_event_copy(dap_chain_cs_dag_event_t *a_event_src,size_t a_event_size)
{
    if(!a_event_src)
        return NULL;
    dap_chain_cs_dag_event_t *l_event_new = DAP_NEW_Z_SIZE(dap_chain_cs_dag_event_t, a_event_size);
    memcpy(l_event_new, a_event_src, a_event_size);
    return l_event_new;
}

/**
 * @brief dap_chain_cs_dag_event_sign_add
 * @param a_event
 * @param l_key
 * @return
 */
size_t dap_chain_cs_dag_event_sign_add(dap_chain_cs_dag_event_t **a_event_ptr, size_t a_event_size, dap_enc_key_t * a_key)
{
    assert(a_event_ptr);
    dap_chain_cs_dag_event_t *l_event = *a_event_ptr;
    // check for re-sign with same key
    if (dap_chain_cs_dag_event_sign_exists(l_event, a_event_size, a_key)) {
        size_t l_pub_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_size);
        dap_hash_fast_t l_pkey_hash = {};
        dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
        DAP_DEL_Z(l_pub_key);
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str(&l_pkey_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        log_it(L_DEBUG, "Sign from this key exists: %s", l_hash_str);
        return 0;
    }
    size_t l_hashes_size = l_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)(l_event->hashes_n_datum_n_signs + l_hashes_size);
    size_t l_datum_size =  dap_chain_datum_size(l_datum);
    size_t l_event_size_excl_sign = sizeof(l_event->header) + l_hashes_size + l_datum_size;
    dap_sign_t *l_sign = dap_sign_create(a_key, l_event, l_event_size_excl_sign, 0);
    size_t l_sign_size = dap_sign_get_size(l_sign);
    *a_event_ptr = l_event = DAP_REALLOC(l_event, a_event_size + l_sign_size);
    size_t l_event_size = a_event_size - sizeof(l_event->header);
    memcpy(l_event->hashes_n_datum_n_signs + l_event_size, l_sign, l_sign_size);
    l_event->header.signs_count++;
    DAP_DELETE(l_sign);
    return a_event_size + l_sign_size;
}

static bool s_sign_exists(uint8_t *a_pos, size_t a_len, dap_enc_key_t *a_key)
{
    size_t l_pub_key_size = 0;
    uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_size);
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

bool dap_chain_cs_dag_event_sign_exists(dap_chain_cs_dag_event_t *a_event, size_t a_event_size, dap_enc_key_t *a_key)
{
    size_t l_hashes_size = a_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)(a_event->hashes_n_datum_n_signs + l_hashes_size);
    size_t l_datum_size =  dap_chain_datum_size(l_datum);
    uint8_t *l_offset = a_event->hashes_n_datum_n_signs + l_hashes_size + l_datum_size;
    size_t l_signs_size = a_event_size - sizeof(a_event->header) - l_hashes_size - l_datum_size;
    return s_sign_exists(l_offset, l_signs_size, a_key);
}

bool dap_chain_cs_dag_event_round_sign_exists(dap_chain_cs_dag_event_round_item_t *a_round_item, dap_enc_key_t *a_key) {
    uint8_t *l_offset = a_round_item->event_n_signs + (size_t)a_round_item->event_size;
    size_t l_signs_size = (size_t)a_round_item->data_size - (size_t)a_round_item->event_size;
    return s_sign_exists(l_offset, l_signs_size, a_key);
}

/**
 * @brief dap_chain_cs_dag_event_get_sign
 * @param a_event
 * @param a_sign_number
 * @return
 */
dap_sign_t * dap_chain_cs_dag_event_get_sign( dap_chain_cs_dag_event_t * a_event, size_t a_event_size, uint16_t a_sign_number)
{
    size_t l_offset_passed = sizeof (a_event->header);
    if (a_event->header.signs_count > a_sign_number ){
        size_t l_offset_to_sign = dap_chain_cs_dag_event_calc_size_excl_signs(a_event,a_event_size);
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

size_t dap_chain_cs_dag_event_round_sign_add(dap_chain_cs_dag_event_round_item_t **a_round_item_ptr, size_t a_round_item_size, dap_enc_key_t *a_key)
{
    dap_chain_cs_dag_event_round_item_t *l_round_item = *a_round_item_ptr;
    if (dap_chain_cs_dag_event_round_sign_exists(l_round_item, a_key))
        return 0;
    dap_sign_t * l_sign = dap_sign_create(a_key, &l_round_item->round_info.datum_hash, sizeof(dap_chain_hash_fast_t), 0);
    size_t l_sign_size = dap_sign_get_size(l_sign);
    size_t l_offset = (size_t)l_round_item->data_size;
    *a_round_item_ptr = l_round_item = DAP_REALLOC(l_round_item, a_round_item_size+l_sign_size);
    memcpy(l_round_item->event_n_signs+l_offset, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    l_round_item->data_size += (uint32_t)l_sign_size;
    return a_round_item_size+l_sign_size;
}

static bool s_event_broadcast_send(dap_chain_cs_dag_event_round_broadcast_t *l_arg) {
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_arg->dag->chain->net_id);
    if (dap_chain_net_get_state(l_net) != NET_STATE_SYNC_GDB) {
        dap_chain_net_sync_gdb_broadcast((void *)l_net, l_arg->op_code, l_arg->group, l_arg->key, l_arg->value, l_arg->value_size);
    }
    else if ( l_arg->attempts < 10 ) {
        l_arg->attempts++;
        return true;
    }
    DAP_DELETE(l_arg->group);
    DAP_DELETE(l_arg->key);
    DAP_DELETE(l_arg->value);
    DAP_DELETE(l_arg);
    return false;
}

void dap_chain_cs_dag_event_broadcast(dap_chain_cs_dag_t *a_dag, const char a_op_code, const char *a_group,
                const char *a_key, const void *a_value, const size_t a_value_size) {
    dap_chain_cs_dag_event_round_broadcast_t *l_arg = DAP_NEW(dap_chain_cs_dag_event_round_broadcast_t);
    l_arg->dag = a_dag;
    l_arg->op_code = a_op_code;
    l_arg->group = dap_strdup(a_group);
    l_arg->key = dap_strdup(a_key);
    l_arg->value = DAP_DUP_SIZE(a_value, a_value_size);
    l_arg->value_size = a_value_size;
    l_arg->attempts = 0;

    if (dap_timerfd_start(3*1000,
                        (dap_timerfd_callback_t)s_event_broadcast_send,
                        l_arg) == NULL) {
        log_it(L_ERROR,"Can't run timer for broadcast Event %s", a_key);
    }
}

bool dap_chain_cs_dag_event_gdb_set(dap_chain_cs_dag_t *a_dag, char *a_event_hash_str, dap_chain_cs_dag_event_t *a_event,
                                    size_t a_event_size, dap_chain_cs_dag_event_round_item_t *a_round_item,
                                    const char *a_group)
{
    size_t l_signs_size = (size_t)(a_round_item->data_size-a_round_item->event_size);
    uint8_t *l_signs = (uint8_t*)a_round_item->event_n_signs + (size_t)a_round_item->event_size;
    dap_chain_cs_dag_event_round_item_t * l_round_item
            = DAP_NEW_SIZE(dap_chain_cs_dag_event_round_item_t,
                           sizeof(dap_chain_cs_dag_event_round_item_t) + a_event_size + l_signs_size);
    if (!l_round_item) {
        log_it(L_ERROR, "Not enough memory for event");
        return false;
    }


    l_round_item->event_size = (uint32_t)a_event_size;
    l_round_item->data_size = (uint32_t)(a_event_size+l_signs_size);

    memcpy(&l_round_item->round_info, &a_round_item->round_info, sizeof(dap_chain_cs_dag_event_round_info_t));
    memcpy(l_round_item->event_n_signs,                 a_event, a_event_size);
    memcpy(l_round_item->event_n_signs + a_event_size,  l_signs, l_signs_size);

    l_round_item->round_info.ts_update = dap_time_now();

    bool ret = dap_chain_global_db_gr_set(a_event_hash_str, l_round_item,
            dap_chain_cs_dag_event_round_item_get_size(l_round_item),
            a_group);

    /*size_t l_round_item_size = dap_chain_cs_dag_event_round_item_get_size(a_round_item);
    dap_chain_cs_dag_event_broadcast(a_dag, DAP_DB$K_OPTYPE_ADD, a_dag->gdb_group_events_round_new,
            a_key, a_round_item, l_round_item_size);*/
    DAP_DELETE(l_round_item);
    return ret;
}

dap_chain_cs_dag_event_t* dap_chain_cs_dag_event_gdb_get(const char *a_event_hash_str, size_t *a_event_size, const char *a_group,
                                                            dap_chain_cs_dag_event_round_info_t * a_event_round_info) {
    size_t l_event_round_item_size = 0;
    dap_chain_cs_dag_event_round_item_t* l_event_round_item =
                (dap_chain_cs_dag_event_round_item_t*)dap_chain_global_db_gr_get(a_event_hash_str, &l_event_round_item_size, a_group );
    if ( l_event_round_item == NULL )
        return NULL;
    size_t l_event_size = (size_t)l_event_round_item->event_size;
    dap_chain_cs_dag_event_t* l_event = DAP_NEW_SIZE(dap_chain_cs_dag_event_t, l_event_size);
    memcpy(a_event_round_info, &l_event_round_item->round_info, sizeof(dap_chain_cs_dag_event_round_info_t));
    memcpy(l_event, l_event_round_item->event_n_signs, l_event_size);
    DAP_DELETE(l_event_round_item);
    *a_event_size = l_event_size;
    return l_event;
}

