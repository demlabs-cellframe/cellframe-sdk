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

#include "dap_common.h"
#include "dap_enc_key.h"

#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_event.h"

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
    l_event_new->header.ts_created = (uint64_t)time(NULL);
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
            l_event_new = (dap_chain_cs_dag_event_t *)DAP_REALLOC(l_event_new, l_event_size + l_sign_size );
            memcpy(l_event_new->hashes_n_datum_n_signs + l_hashes_size + l_datum_size, l_sign, l_sign_size);
            l_event_size += l_sign_size;
            if (a_event_size)
                *a_event_size = l_event_size;
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
dap_chain_cs_dag_event_t * dap_chain_cs_dag_event_copy_with_sign_add( dap_chain_cs_dag_event_t * a_event, size_t a_event_size, 
                                                            size_t * a_event_size_new,
                                                            dap_chain_net_t * a_net, dap_enc_key_t * a_key)
{
    size_t l_hashes_size = a_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)(a_event->hashes_n_datum_n_signs + l_hashes_size);
    size_t l_datum_size =  dap_chain_datum_size(l_datum);
    size_t l_event_size_excl_sign = sizeof(a_event->header)+l_hashes_size+l_datum_size;
    // size_t l_event_size_excl_sign = dap_chain_cs_dag_event_calc_size_excl_signs(a_event,a_event_size);
    size_t l_event_size = a_event_size;
    size_t l_event_signs_size = l_event_size - l_event_size_excl_sign;
    dap_sign_t * l_sign = dap_sign_create(a_key,a_event,l_event_size_excl_sign,0);

    size_t l_sign_size = dap_sign_get_size(l_sign);
    dap_chain_addr_t l_addr = {0};
    dap_chain_hash_fast_t l_pkey_hash;
    dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
    dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, a_net->pub.id);
    char * l_addr_str = dap_chain_addr_to_str(&l_addr);

    size_t l_offset = l_hashes_size+l_datum_size;
    // checking re-sign from one address and calc signs size
    while ( l_offset+sizeof(a_event->header) < l_event_size  ) {
        dap_sign_t * l_item_sign = (dap_sign_t *)(a_event->hashes_n_datum_n_signs +l_offset);
        size_t l_sign_size = dap_sign_get_size(l_item_sign);
        dap_chain_addr_t l_item_addr = {0};
        dap_chain_hash_fast_t l_item_pkey_hash;
        dap_sign_get_pkey_hash(l_item_sign, &l_item_pkey_hash);
        dap_chain_addr_fill(&l_item_addr, l_item_sign->header.type, &l_item_pkey_hash, a_net->pub.id);
        // checking re-sign from one address
        if (memcmp(&l_addr, &l_item_addr, sizeof(l_item_addr)) == 0) {
            log_it(L_DEBUG, "Sign from this addr exists: %s", l_addr_str);
            DAP_DELETE(l_sign);
            DAP_DELETE(l_addr_str);
            return NULL;
        }
        l_offset += l_sign_size;
    }
    // dap_chain_cs_dag_event_t * l_event_new = DAP_REALLOC(a_event, l_event_size+l_sign_size);
    dap_chain_cs_dag_event_t * l_event_new = DAP_NEW_Z_SIZE(dap_chain_cs_dag_event_t, l_event_size+l_sign_size);
    memcpy(l_event_new, a_event, l_event_size);
    memcpy(l_event_new->hashes_n_datum_n_signs+l_offset, l_sign, l_sign_size);
    *a_event_size_new = l_event_size+l_sign_size;
    l_event_new->header.signs_count++;
    DAP_DELETE(l_sign);
    DAP_DELETE(l_addr_str);
    return l_event_new;
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
            l_signs_offset+=l_sign->header.sign_pkey_size+l_sign->header.sign_size+sizeof(l_sign->header);
            l_offset_passed += l_offset_to_sign;
            if ( l_offset_passed >= a_event_size)
                return NULL;
        }
        return (dap_sign_t*) l_signs + l_signs_offset;
    }else
        return NULL;
}

bool dap_chain_cs_dag_event_gdb_set(char *a_event_hash_str, dap_chain_cs_dag_event_t * a_event, size_t a_event_size,
                                    const char *a_group, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg) {
    dap_chain_cs_dag_event_round_item_t * l_event_round_item = DAP_NEW_SIZE(dap_chain_cs_dag_event_round_item_t,
                                                                            sizeof(dap_chain_cs_dag_event_round_item_t)+a_event_size );
    l_event_round_item->event_size = a_event_size;
    a_event_round_cfg->ts_update = (uint64_t)time(NULL);
    // l_event_round_item->event = DAP_DUP_SIZE(a_event, a_event_size);
    memcpy(&l_event_round_item->cfg, a_event_round_cfg, sizeof(dap_chain_cs_dag_event_round_cfg_t));
    memcpy(l_event_round_item->event, a_event, a_event_size);
    bool ret = dap_chain_global_db_gr_set(dap_strdup(a_event_hash_str), (uint8_t *)l_event_round_item,
            dap_chain_cs_dag_event_round_item_get_size(l_event_round_item),
            a_group);
    DAP_DELETE(l_event_round_item);
    return ret;
}

dap_chain_cs_dag_event_t* dap_chain_cs_dag_event_gdb_get(const char *a_event_hash_str, size_t * a_event_size, const char *a_group,
                                                            dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg) {
    size_t l_event_round_item_size = 0;
    dap_chain_cs_dag_event_round_item_t* l_event_round_item = 
                (dap_chain_cs_dag_event_round_item_t*)dap_chain_global_db_gr_get(a_event_hash_str, &l_event_round_item_size, a_group );
    if ( l_event_round_item == NULL )
        return NULL;
    size_t l_event_size = l_event_round_item->event_size;
    dap_chain_cs_dag_event_t* l_event = DAP_NEW_SIZE(dap_chain_cs_dag_event_t, l_event_size);
    memcpy(a_event_round_cfg, &l_event_round_item->cfg, sizeof(dap_chain_cs_dag_event_round_cfg_t));
    memcpy(l_event, l_event_round_item->event, l_event_size);
    DAP_DELETE(l_event_round_item);
    *a_event_size = l_event_size;
    return l_event;
}


