/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <memory.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
//#include "dap_enc_http.h"
#include "dap_enc_http.h"
//#include "dap_http.h"
#include "http_status_code.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_enc.h"
#include <dap_enc_http.h>
#include <dap_enc_key.h>
#include <dap_enc_ks.h>
#include "dap_chain_mempool.h"

#include "dap_common.h"
#include "dap_list.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"

#define LOG_TAG "dap_chain_mempool"


int dap_datum_mempool_init(void)
{
    return 0;
}

/**
 * @brief dap_chain_mempool_datum_add
 * @param a_datum
 * @return
 */
int dap_chain_mempool_datum_add(dap_chain_datum_t * a_datum, dap_chain_t * a_chain )
{
    if( a_datum == NULL){
        log_it(L_ERROR, "NULL datum trying to add in mempool");
        return -1;
    }
    int ret =0;

    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(a_datum->data , a_datum->header.data_size, &l_key_hash);

    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);
    if(dap_chain_global_db_gr_set(dap_strdup(l_key_str), (byte_t *) a_datum, dap_chain_datum_size(a_datum)
            ,l_gdb_group)) {
        log_it(L_NOTICE, "Datum with data's hash %s was placed in mempool", l_key_str);
    }else{
        log_it(L_WARNING, "Can't place data's hash %s was placed in mempool", l_key_str);
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);
    return ret;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
dap_hash_fast_t* dap_chain_mempool_tx_create(dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const dap_chain_addr_t* a_addr_fee,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint64_t a_value, uint64_t a_value_fee)
{
    // check valid param
    if(!a_chain | !a_key_from || ! a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_to) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value)
        return NULL;

    // find the transactions from which to take away coins
    uint64_t l_value_transfer = 0; // how many coins to transfer
    uint64_t l_value_need = a_value + a_value_fee;
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
                                                                             a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING,"Not enough funds to transfer");
        return NULL;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint64_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(l_value_to_items == l_value_transfer);
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out' items
    {
        uint64_t l_value_pack = 0; // how much datoshi add to 'out' items
        if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) == 1) {
            l_value_pack += a_value;
            // transaction fee
            if(a_addr_fee) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_fee, a_value_fee) == 1)
                    l_value_pack += a_value_fee;
            }
        }
        // coin back
        uint64_t l_value_back = l_value_transfer - l_value_pack;
        if(l_value_back) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_hash_fast_t * l_ret = DAP_NEW_Z(dap_hash_fast_t);
    dap_hash_fast(l_tx, l_tx_size, l_ret);
    DAP_DELETE(l_tx);
    if(dap_chain_mempool_datum_add (l_datum, a_chain) == 0){
        return l_ret;
    }else{
        DAP_DELETE( l_datum );
        DAP_DELETE(l_ret);
        return NULL;
    }
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create_massive( dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const dap_chain_addr_t* a_addr_fee,
        const char a_token_ticker[10],
        uint64_t a_value, uint64_t a_value_fee,size_t a_tx_num)
{
    // check valid param
    if(!a_chain | !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_to) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value || !a_tx_num){
        log_it(L_ERROR, "Wrong parameters in dap_chain_mempool_tx_create_massive() call");
        return -1;

    }
    dap_global_db_obj_t * l_objs = DAP_NEW_Z_SIZE(dap_global_db_obj_t, (a_tx_num+1)*sizeof (dap_global_db_obj_t) );



    // Search unused out:
    uint64_t l_value_need =a_tx_num*( a_value + a_value_fee );
    uint64_t l_value_transfer = 0; // how many coins to transfer
    log_it(L_DEBUG,"Create %lu transactions, summary %Lf.7", a_tx_num,dap_chain_datoshi_to_coins(l_value_need) ) ;
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
                                                                             a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING,"Not enough funds to transfer");
        return -2;
    }

    for (size_t i=0; i< a_tx_num ; i++){
        log_it(L_DEBUG, "Prepare tx %u",i);
        // find the transactions from which to take away coins

        // create empty transaction
        dap_chain_datum_tx_t *l_tx_new = dap_chain_datum_tx_create();
        uint64_t l_value_back=0;
        // add 'in' items
        dap_list_t *l_list_tmp = l_list_used_out;
        uint64_t l_value_to_items = 0; // how many coins to transfer

        // Add in and remove out used items
        while(l_list_tmp) {
            list_used_item_t *item = l_list_tmp->data;
            char l_in_hash_str[70];

            dap_chain_hash_fast_to_str(&item->tx_hash_fast,l_in_hash_str,sizeof (l_in_hash_str) );

            if(dap_chain_datum_tx_add_in_item(&l_tx_new, &item->tx_hash_fast, (uint32_t) item->num_idx_out) == 1) {
                l_value_to_items += item->value;
                log_it(L_DEBUG,"Added input %s with %llu datoshi",l_in_hash_str, item->value);
            }else{
                log_it(L_WARNING,"Can't add input from %s with %llu datoshi",l_in_hash_str, item->value);
            }
            l_list_used_out = l_list_tmp->next;
            DAP_DELETE(l_list_tmp->data);
            dap_list_free1(l_list_tmp);
            l_list_tmp = l_list_used_out;
            if ( l_value_to_items >= l_value_transfer )
                break;
        }
        if ( l_value_to_items <  (a_value + a_value_fee) ){
            log_it(L_ERROR,"Not enought values on output %llu to produce enought ins %llu when need %llu",
                   l_value_to_items, l_value_transfer,
                   l_value_need);
            return -5;
        }

        // add 'out' items
        uint64_t l_value_pack = 0; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_item(&l_tx_new, a_addr_to, a_value) == 1) {
            l_value_pack += a_value;
            // transaction fee
            if(a_addr_fee) {
                if(dap_chain_datum_tx_add_out_item(&l_tx_new, a_addr_fee, a_value_fee) == 1)
                    l_value_pack += a_value_fee;
            }
        }
        // coin back
        l_value_back = l_value_transfer - l_value_pack;
        if(l_value_back) {
            //log_it(L_DEBUG,"Change back %llu", l_value_back);
            if(dap_chain_datum_tx_add_out_item(&l_tx_new, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx_new);
                return -3;
            }
        }

        // add 'sign' items
        if(dap_chain_datum_tx_add_sign_item(&l_tx_new, a_key_from) != 1) {
            dap_chain_datum_tx_delete(l_tx_new);
            return -1;
        }
        // now tx is formed - calc size and hash
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx_new);

        dap_chain_hash_fast_t l_tx_new_hash;
        dap_hash_fast(l_tx_new, l_tx_size, &l_tx_new_hash);
        // If we have value back - update balance cache
        if(l_value_back) {
            //log_it(L_DEBUG,"We have value back %llu now lets see how many outputs we have", l_value_back);
            int l_item_count = 0;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get( l_tx_new, TX_ITEM_TYPE_OUT,
                    &l_item_count);
            dap_list_t *l_list_tmp = l_list_out_items;
            int l_out_idx_tmp = 0; // current index of 'out' item
            //log_it(L_DEBUG,"We have %d outputs in new TX", l_item_count);
            while(l_list_tmp) {
                dap_chain_tx_out_t * l_out = l_list_tmp->data ;
                if( ! l_out){
                    log_it(L_WARNING, "Output is NULL, continue check outputs...");
                    l_out_idx_tmp++;
                    continue;
                }
                if ( memcmp(&l_out->addr, a_addr_from, sizeof (*a_addr_from))==0 ){
                    list_used_item_t *l_item_back = DAP_NEW(list_used_item_t);
                    memcpy(&l_item_back->tx_hash_fast, &l_tx_new_hash, sizeof(dap_chain_hash_fast_t));
                    l_item_back->num_idx_out = l_out_idx_tmp;
                    l_item_back->value = l_value_back;
                    l_list_used_out = dap_list_prepend(l_list_used_out, l_item_back);
                    log_it(L_DEBUG,"Found change back output, stored back in UTXO table");
                    break;
                 }
                l_list_tmp = l_list_tmp->next;
                l_out_idx_tmp++;
            }
            //log_it(L_DEBUG,"Checked all outputs");
            dap_list_free( l_list_out_items);
        }
        l_value_transfer -= l_value_pack;

        // Now produce datum
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx_new, l_tx_size);

        dap_chain_datum_tx_delete(l_tx_new);
        //dap_chain_ledger_tx_add( a_chain->ledger, l_tx);

        l_objs[i].key = dap_chain_hash_fast_to_str_new(&l_tx_new_hash);
        //continue;
        l_objs[i].value = (uint8_t*) l_datum;
        l_objs[i].value_len = l_tx_size + sizeof(l_datum->header);
        log_it(L_DEBUG, "Prepared obj with key %s (value_len = %llu)",
               l_objs[i].key? l_objs[i].key :"NULL" , l_objs[i].value_len );

    }
    dap_list_free_full(l_list_used_out, free);

    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);

    //return 0;
    if( dap_chain_global_db_gr_save(l_objs,a_tx_num,l_gdb_group) ) {
        log_it(L_NOTICE, "%u transaction are placed in mempool", a_tx_num);
        //DAP_DELETE(l_objs);
        DAP_DELETE(l_gdb_group);
        return 0;
    }else{
        log_it(L_ERROR, "Can't place %u transactions  in mempool", a_tx_num);
        //DAP_DELETE(l_objs);
        DAP_DELETE(l_gdb_group);
        return -4;
    }


}

dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond_input(dap_chain_net_t * a_net,dap_chain_hash_fast_t *a_tx_prev_hash,
                                                              const dap_chain_addr_t* a_addr_to, dap_enc_key_t *l_key_tx_sign,
                                                              dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size)
{
    UNUSED(l_receipt_size);
    dap_ledger_t * l_ledger = a_net ? dap_chain_ledger_by_net_name( a_net->pub.name ) : NULL;
    if ( ! a_net || ! l_ledger || ! a_addr_to )
        return NULL;
    if ( ! dap_chain_addr_check_sum (a_addr_to) ){
        log_it(L_ERROR, "Wrong address_to checksum");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    uint16_t pos=0;
    dap_chain_datum_tx_add_item(&l_tx, (byte_t*) l_receipt);
    pos++;
    uint64_t l_value_send = l_receipt->receipt_info.value_datoshi;

    // add 'in_cond' items
    dap_chain_datum_tx_t *l_tx_cond = dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_prev_hash);
    int l_prev_cond_idx;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_cond, &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, a_tx_prev_hash, l_prev_cond_idx)) {
        dap_chain_datum_tx_t *l_tx_tmp;
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 }; // start hash
        dap_chain_tx_out_cond_t *l_tmp_cond;
        uint64_t l_value_cond = 0;
        int l_tmp_cond_idx;
        // Find all transactions
        while (l_value_cond < l_value_send) {
            l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(l_ledger, &l_tx_cur_hash, &l_tmp_cond, &l_tmp_cond_idx, NULL);
            if (!l_tx_tmp) {
                break;
            }
            if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_cur_hash, l_tmp_cond_idx))
                continue;
            if (l_tmp_cond->header.subtype != l_out_cond->header.subtype)
                continue;
            if (l_tmp_cond->subtype.srv_pay.srv_uid.uint64 != l_out_cond->subtype.srv_pay.srv_uid.uint64)
                continue;
            if (l_tmp_cond->subtype.srv_pay.unit.uint32 != l_out_cond->subtype.srv_pay.unit.uint32)
                continue;
            if (l_tmp_cond->subtype.srv_pay.unit_price_max_datoshi != l_out_cond->subtype.srv_pay.unit_price_max_datoshi)
                continue;
            if (memcmp(&l_tmp_cond->subtype.srv_pay.pkey_hash, &l_out_cond->subtype.srv_pay.pkey_hash, sizeof(dap_chain_hash_fast_t)))
                continue;
            l_value_cond = l_tmp_cond->header.value;
        }
        if (l_value_cond < l_value_send) {
            log_it(L_WARNING, "Requested conditional transaction is already used out");
            return NULL;
        }
    }
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_prev_hash, l_prev_cond_idx, pos-1) != 0 ){
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Cant add tx cond input");
        return NULL;
    }

    // add 'out' item
    if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, l_value_send) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Cant add tx output");
        return NULL;
    }

    //add 'out_cond' item
    size_t l_size = dap_chain_datum_item_tx_get_size((uint8_t *)l_out_cond);
    dap_chain_tx_out_cond_t *l_out_cond_new = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, l_size);
    memcpy(l_out_cond_new, l_out_cond, l_size);
    l_out_cond_new->header.value -= l_value_send;
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond_new);
    DAP_DELETE(l_out_cond_new);

    // add 'sign' items
    if (l_key_tx_sign){
        if(dap_chain_datum_tx_add_sign_item(&l_tx, l_key_tx_sign) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Can't add sign output");
            return NULL;
        }
    }
    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );

    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash );
    DAP_DELETE( l_tx );

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );

    char * l_gdb_group;
    if(a_net->pub.default_chain)
        l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_net->pub.default_chain);
    else
        l_gdb_group = dap_chain_net_get_gdb_group_mempool_by_chain_type( a_net ,CHAIN_TYPE_TX);

    if( dap_chain_global_db_gr_set( dap_strdup(l_key_str), (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
                                   , l_gdb_group ) ) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}


/**
 * Make transfer transaction
 *
 * return dap_chain_datum_t, NULL if Error
 */
static dap_chain_datum_t* dap_chain_tx_create_cond(dap_chain_net_t * a_net,
        dap_enc_key_t *a_key_from, dap_enc_key_t *a_key_cond,
        const dap_chain_addr_t* a_addr_from,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint64_t a_value,uint64_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint64_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    dap_ledger_t * l_ledger = a_net ? dap_chain_ledger_by_net_name( a_net->pub.name ) : NULL;
    // check valid param
    if(!a_net || ! l_ledger || !a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) ||
            !a_value)
        return NULL;

    // find the transactions from which to take away coins
    uint64_t l_value_transfer = 0; // how many coins to transfer
    uint64_t l_value_need = a_value + a_value_fee;
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                             a_addr_from, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        log_it( L_ERROR, "nothing to tranfer (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint64_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(l_value_to_items == l_value_transfer);
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out_cond' and 'out' items
    {
        uint64_t l_value_pack = 0; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_key_cond, a_srv_uid, a_value, a_value_per_unit_max, a_unit, a_cond,
                a_cond_size) == 1) {
            l_value_pack += a_value;
            // transaction fee
            if(a_value_fee) {
                // TODO add condition with fee for mempool-as-service
            }
        }
        // coin back
        uint64_t l_value_back = l_value_transfer - l_value_pack;
        if(l_value_back) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it( L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );

    return l_datum;
    /*dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash );
    DAP_DELETE( l_tx );

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool_by_chain_type( a_net ,CHAIN_TYPE_TX);
    if( dap_chain_global_db_gr_set( dap_strdup(l_key_str), (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
                                   , l_gdb_group ) ) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;*/
}

/**
 * Make transfer transaction & insert to database
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
dap_chain_hash_fast_t* dap_chain_proc_tx_create_cond(dap_chain_net_t * a_net,
        dap_enc_key_t *a_key_from, dap_enc_key_t *a_key_cond,
        const dap_chain_addr_t* a_addr_from,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint64_t a_value,uint64_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint64_t a_value_fee, const void *a_cond, size_t a_cond_size)
{

    dap_chain_t *l_chain = NULL;
    if(a_net->pub.default_chain)
        l_chain = a_net->pub.default_chain;
    else
        l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_TX);

    if(!l_chain)
            return NULL;
    // Make transfer transaction
    dap_chain_datum_t *l_datum = dap_chain_tx_create_cond(a_net,a_key_from, a_key_cond, a_addr_from,
            a_token_ticker,a_value,a_value_per_unit_max, a_unit,
            a_srv_uid, a_value_fee, a_cond, a_cond_size);

    if(!l_datum)
        return NULL;
    size_t l_datums_number = l_chain->callback_add_datums(l_chain, &l_datum, 1);
    if(!l_datums_number)
            return NULL;

    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)&(l_datum->data);
    size_t l_tx_size = l_datum->header.data_size;

    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash );
    //DAP_DELETE( l_tx );

    return l_key_hash;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond(dap_chain_net_t * a_net,
        dap_enc_key_t *a_key_from, dap_enc_key_t *a_key_cond,
        const dap_chain_addr_t* a_addr_from,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint64_t a_value,uint64_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint64_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    // Make transfer transaction
    dap_chain_datum_t *l_datum = dap_chain_tx_create_cond(a_net,a_key_from, a_key_cond, a_addr_from,
            a_token_ticker,a_value,a_value_per_unit_max, a_unit,
            a_srv_uid, a_value_fee, a_cond, a_cond_size);

    if(!l_datum)
        return NULL;

    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)&(l_datum->data);
    size_t l_tx_size = l_datum->header.data_size;//dap_chain_datum_tx_get_size( l_tx );

    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash );
    //DAP_DELETE( l_tx );

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool_by_chain_type( a_net ,CHAIN_TYPE_TX);
    if( dap_chain_global_db_gr_set( dap_strdup(l_key_str), (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
                                   , l_gdb_group ) ) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}

/**
 * Make receipt transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create_receipt(uint64_t a_value)
//(dap_enc_key_t *a_key_from, dap_enc_key_t *a_key_cond,
//        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_cond,
//        const dap_chain_addr_t* a_addr_fee, const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
//        uint64_t a_value, uint64_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    // check valid param
/*    if(!a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_cond) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value)
        return -1;*/
/*
    // find the transactions from which to take away coins
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint64_t l_value_transfer = 0; // how many coins to transfer
    {
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
        uint64_t l_value_need = a_value + a_value_fee;
        while(l_value_transfer < l_value_need)
        {
            // Get the transaction in the cache by the addr in out item
            const dap_chain_datum_tx_t *l_tx = dap_chain_ledger_tx_find_by_addr(a_addr_from,
                    &l_tx_cur_hash);
            if(!l_tx)
                break;
            // Get all item from transaction by type
            int l_item_count = 0;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) l_tx, TX_ITEM_TYPE_OUT,
                    &l_item_count);
            dap_list_t *l_list_tmp = l_list_out_items;
            int l_out_idx_tmp = 0; // current index of 'out' item
            while(l_list_tmp) {
                dap_chain_tx_out_t *out_item = l_list_tmp->data;
                // if 'out' item has addr = a_addr_from
                if(out_item && &out_item->addr && !memcmp(a_addr_from, &out_item->addr, sizeof(dap_chain_addr_t))) {

                    // Check whether used 'out' items
                    if(!dap_chain_ledger_tx_hash_is_used_out_item(&l_tx_cur_hash, l_out_idx_tmp)) {

                        list_used_item_t *item = DAP_NEW(list_used_item_t);
                        memcpy(&item->tx_hash_fast, &l_tx_cur_hash, sizeof(dap_chain_hash_fast_t));
                        item->num_idx_out = l_out_idx_tmp;
                        item->value = out_item->header.value;
                        l_list_used_out = dap_list_append(l_list_used_out, item);
                        l_value_transfer += item->value;
                        // already accumulated the required value, finish the search for 'out' items
                        if(l_value_transfer >= l_value_need) {
                            break;
                        }
                    }
                }
                // go to the next 'out' item in l_tx transaction
                l_out_idx_tmp++;
                l_list_tmp = dap_list_next(l_list_tmp);
            }
            dap_list_free(l_list_out_items);
        }

        // nothing to tranfer (not enough funds)
        if(!l_list_used_out || l_value_transfer < l_value_need) {
            dap_list_free_full(l_list_used_out, free);
            return -2;
        }
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        dap_list_t *l_list_tmp = l_list_used_out;
        uint64_t l_value_to_items = 0; // how many coins to transfer
        while(l_list_tmp) {
            list_used_item_t *item = l_list_tmp->data;
            if(dap_chain_datum_tx_add_in_item(&l_tx, &item->tx_hash_fast, item->num_idx_out) == 1) {
                l_value_to_items += item->value;
            }
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        assert(l_value_to_items == l_value_transfer);
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out_cond' and 'out' items
    {
        uint64_t l_value_pack = 0; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_key_cond, (dap_chain_addr_t*) a_addr_cond, a_value, a_cond,
                a_cond_size) == 1) {
            l_value_pack += a_value;
            // transaction fee
            if(a_addr_fee) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_fee, a_value_fee) == 1)
                    l_value_pack += a_value_fee;
            }
        }
        // coin back
        uint64_t l_value_back = l_value_transfer - l_value_pack;
        if(l_value_back) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return -1;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return -1;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);

    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_tx, l_tx_size, &l_key_hash);
    DAP_DELETE(l_tx);

    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    if(dap_chain_global_db_gr_set(dap_strdup(l_key_str), (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
            , c_dap_datum_mempool_gdb_group)) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
        // add transaction to ledger
        if(dap_chain_ledger_tx_add((dap_chain_datum_tx_t*) l_datum->data) < 0)
            log_it(L_ERROR, "Transaction %s not placed in LEDGER", l_key_str);
    }
    DAP_DELETE(l_key_str);*/

    return 0;
}

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size)
{
    size_t a_request_size = 2 * sizeof(uint16_t), shift_size = 0;
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        a_request_size += dap_chain_datum_size(datum_mempool->data[i]) + sizeof(uint16_t);
    }
    uint8_t *a_request = DAP_NEW_SIZE(uint8_t, a_request_size);
    memcpy(a_request + shift_size, &(datum_mempool->version), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    memcpy(a_request + shift_size, &(datum_mempool->datum_count), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = dap_chain_datum_size(datum_mempool->data[i]);
        memcpy(a_request + shift_size, &size_one, sizeof(uint16_t));
        shift_size += sizeof(uint16_t);
        memcpy(a_request + shift_size, datum_mempool->data[i], size_one);
        shift_size += size_one;
    }
    assert(shift_size == a_request_size);
    if(size)
        *size = a_request_size;
    return a_request;
}

dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *a_datum_mempool_ser, size_t a_datum_mempool_ser_size)
{
    size_t shift_size = 0;
    //uint8_t *a_datum_mempool_ser = DAP_NEW_Z_SIZE(uint8_t, datum_mempool_size / 2 + 1);
    //datum_mempool_size = hex2bin(a_datum_mempool_ser, datum_mempool_str_in, datum_mempool_size) / 2;
    dap_datum_mempool_t *datum_mempool = DAP_NEW_Z(dap_datum_mempool_t);
    memcpy(&(datum_mempool->version), a_datum_mempool_ser + shift_size, sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    memcpy(&(datum_mempool->datum_count), a_datum_mempool_ser + shift_size, sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    datum_mempool->data = DAP_NEW_Z_SIZE(dap_chain_datum_t*, datum_mempool->datum_count * sizeof(dap_chain_datum_t*));
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = 0;
        memcpy(&size_one, a_datum_mempool_ser + shift_size, sizeof(uint16_t));
        shift_size += sizeof(uint16_t);
        datum_mempool->data[i] = (dap_chain_datum_t*) DAP_NEW_Z_SIZE(uint8_t, size_one);
        memcpy(datum_mempool->data[i], a_datum_mempool_ser + shift_size, size_one);
        shift_size += size_one;
    }
    assert(shift_size == a_datum_mempool_ser_size);
    DAP_DELETE(a_datum_mempool_ser);
    return datum_mempool;
}

void dap_datum_mempool_clean(dap_datum_mempool_t *datum)
{
    if(!datum)
        return;
    for(int i = 0; i < datum->datum_count; i++) {
        DAP_DELETE(datum->data[i]);
    }
    DAP_DELETE(datum->data);
    datum->data = NULL;
}

void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
}

/**
 *
 */
static char* calc_datum_hash(const char *datum_str, size_t datum_size)
{
    dap_chain_hash_fast_t a_hash;
    dap_hash_fast( datum_str, datum_size, &a_hash);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);

//    size_t hash_len = dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);
    dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);

//    if(!hash_len) {
//        DAP_DELETE(a_str);
//        return NULL;
//    }

    return a_str;
}

static void enc_http_reply_encode_new(struct dap_http_simple *a_http_simple, dap_enc_key_t * key,
        enc_http_delegate_t * a_http_delegate)
{
    //dap_enc_key_t * key = dap_enc_ks_find_http(a_http_simple->http);
    if(key == NULL) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if(a_http_delegate->response) {

        if(a_http_simple->reply)
            free(a_http_simple->reply);

        size_t l_reply_size_max = dap_enc_code_out_size(a_http_delegate->key,
                a_http_delegate->response_size,
                DAP_ENC_DATA_TYPE_RAW);

        a_http_simple->reply = DAP_NEW_SIZE(void, l_reply_size_max);
        a_http_simple->reply_size = dap_enc_code(a_http_delegate->key,
                a_http_delegate->response, a_http_delegate->response_size,
                a_http_simple->reply, l_reply_size_max,
                DAP_ENC_DATA_TYPE_RAW);

        /*/ decode test
         size_t l_response_dec_size_max = a_http_simple->reply_size ? a_http_simple->reply_size * 2 + 16 : 0;
         char * l_response_dec = a_http_simple->reply_size ? DAP_NEW_Z_SIZE(char, l_response_dec_size_max) : NULL;
         size_t l_response_dec_size = 0;
         if(a_http_simple->reply_size)
         l_response_dec_size = dap_enc_decode(a_http_delegate->key,
         a_http_simple->reply, a_http_simple->reply_size,
         l_response_dec, l_response_dec_size_max,
         DAP_ENC_DATA_TYPE_RAW);
         l_response_dec_size_max = 0;*/
    }

}

/**
 * @brief
 * @param cl_st HTTP server instance
 * @param arg for return code
 */
void chain_mempool_proc(struct dap_http_simple *cl_st, void * arg)
{
    http_status_code_t * return_code = (http_status_code_t*) arg;
    // save key while it alive, i.e. still exist
    dap_enc_key_t *key = dap_enc_ks_find_http(cl_st->http_client);
    //dap_enc_key_serealize_t *key_ser = dap_enc_key_serealize(key_tmp);
    //dap_enc_key_t *key = dap_enc_key_deserealize(key_ser, sizeof(dap_enc_key_serealize_t));

    // read header
    dap_http_header_t *hdr_session_close_id =
            (cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);
    if(dg) {
        char *suburl = dg->url_path;
        char *request_str = dg->request_str;
        int request_size = (int) dg->request_size;
        //printf("!!***!!! chain_mempool_proc arg=%d suburl=%s str=%s len=%d\n", arg, suburl, request_str, request_size);
        if(request_str && request_size > 1) {
            //  find what to do
            uint8_t action = DAP_DATUM_MEMPOOL_NONE; //*(uint8_t*) request_str;
            if(dg->url_path_size > 0) {
                if(!strcmp(suburl, "add"))
                    action = DAP_DATUM_MEMPOOL_ADD;
                else if(!strcmp(suburl, "check"))
                    action = DAP_DATUM_MEMPOOL_CHECK;
                else if(!strcmp(suburl, "del"))
                    action = DAP_DATUM_MEMPOOL_DEL;
            }
            dap_datum_mempool_t *datum_mempool =
                    (action != DAP_DATUM_MEMPOOL_NONE) ?
                            dap_datum_mempool_deserialize((uint8_t*) request_str, (size_t) request_size) : NULL;
            if(datum_mempool)
            {
                dap_datum_mempool_free(datum_mempool);
                char *a_key = calc_datum_hash(request_str, (size_t) request_size);
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD: // add datum in base
                    //a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                    //bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                    if(dap_chain_global_db_gr_set(dap_strdup(a_key), request_str,(size_t) request_size,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        *return_code = Http_Status_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == Http_Status_OK) ? "OK" : "False!");
                    DAP_DELETE(a_key);
                    break;

                case DAP_DATUM_MEMPOOL_CHECK: // check datum in base

                    strcpy(cl_st->reply_mime, "text/text");
                    char *str = (char*) dap_chain_global_db_gr_get( dap_strdup(a_key) , NULL,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"));
                    if(str) {
                        dg->response = strdup("1");
                        DAP_DELETE(str);
                        log_it(L_INFO, "Check hash: key=%s result: Present", a_key);
                    }
                    else
                    {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Check hash: key=%s result: Absent", a_key);
                    }
                    dg->response_size = strlen(dg->response);
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                case DAP_DATUM_MEMPOOL_DEL: // delete datum in base
                    strcpy(cl_st->reply_mime, "text/text");
                    if(dap_chain_global_db_gr_del( dap_strdup(a_key),
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        dg->response = strdup("1");

                        log_it(L_INFO, "Delete hash: key=%s result: Ok", a_key);
                    }
                    else
                    {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Delete hash: key=%s result: False!", a_key);
                    }
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                default: // unsupported command
                    log_it(L_INFO, "Unknown request=%s! key=%s", (suburl) ? suburl : "-", a_key);
                    DAP_DELETE(a_key);
                    enc_http_delegate_delete(dg);
                    if(key)
                        dap_enc_key_delete(key);
                    return;
                }
                DAP_DELETE(a_key);
            }
            else
                *return_code = Http_Status_BadRequest;
        }
        else
            *return_code = Http_Status_BadRequest;
        enc_http_delegate_delete(dg);
    }
    else {
        *return_code = Http_Status_Unauthorized;
    }
    if(hdr_session_close_id && hdr_session_close_id->value && !strcmp(hdr_session_close_id->value, "yes")) {
        // close session
        if(hdr_key_id && hdr_key_id->value) {
            dap_enc_ks_delete(hdr_key_id->value);
        }
    }
}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(dap_http_t * a_http_server, const char * a_url)
{
    dap_http_simple_proc_add(a_http_server, a_url, 4096, chain_mempool_proc);
}
