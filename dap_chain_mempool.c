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

//#include <dap_http_simple.h>
//#include <http_status_code.h>
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
#include "dap_chain_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_utxo.h"
#include "dap_chain_datum_tx_items.h"

#define LOG_TAG "dap_chain_mempool"

typedef struct list_used_item {
    dap_chain_hash_fast_t tx_hash_fast;
    int num_idx_out;
    uint64_t value;

//dap_chain_tx_out_t *tx_out;
} list_used_item_t;

const char* c_dap_datum_mempool_gdb_group = NULL;

int dap_datum_mempool_init(void)
{
    c_dap_datum_mempool_gdb_group = dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool");
    return 0;
}

/**
 * @brief dap_chain_mempool_datum_add
 * @param a_datum
 * @return
 */
int dap_chain_mempool_datum_add(dap_chain_datum_t * a_datum)
{
    return 0;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create(dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const dap_chain_addr_t* a_addr_fee,
        const char a_token_ticker[10],
        uint64_t a_value, uint64_t a_value_fee)
{
    // check valid param
    if(!a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_to) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value)
        return -1;

    // find the transactions from which to take away coins
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint64_t l_value_transfer = 0; // how many coins to transfer
    {
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
        uint64_t l_value_need = a_value + a_value_fee;
        while(l_value_transfer < l_value_need)
        {
            // Get the transaction in the cache by the addr in out item
            const dap_chain_datum_tx_t *l_tx = dap_chain_utxo_tx_find_by_addr(a_addr_from,
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
                    if(!dap_chain_utxo_tx_hash_is_used_out_item(&l_tx_cur_hash, l_out_idx_tmp)) {

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
    // add 'out' items
    {
        uint64_t l_value_pack = 0; // how much coin add to 'out' items
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
    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
            , c_dap_datum_mempool_gdb_group)) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
        // add transaction to utxo
        if(dap_chain_utxo_tx_add((dap_chain_datum_tx_t*) l_datum->data)<0)
            log_it(L_ERROR, "Transaction %s not placed in UTXO", l_key_str);
    }
    DAP_DELETE(l_key_str);

    return 0;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 1 Ok, 0 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create_cond(dap_enc_key_t *a_key_from, dap_enc_key_t *a_key_cond,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_cond,
        const dap_chain_addr_t* a_addr_fee, const char a_token_ticker[10],
        uint64_t a_value, uint64_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    // check valid param
    if(!a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_cond) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value)
        return -1;

    // find the transactions from which to take away coins
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint64_t l_value_transfer = 0; // how many coins to transfer
    {
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
        uint64_t l_value_need = a_value + a_value_fee;
        while(l_value_transfer < l_value_need)
        {
            // Get the transaction in the cache by the addr in out item
            const dap_chain_datum_tx_t *l_tx = dap_chain_utxo_tx_find_by_addr(a_addr_from,
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
                    if(!dap_chain_utxo_tx_hash_is_used_out_item(&l_tx_cur_hash, l_out_idx_tmp)) {

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
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_key_cond, (dap_chain_addr_t*)a_addr_cond, a_value, a_cond, a_cond_size) == 1) {
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
    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum, dap_chain_datum_size(l_datum)
            , c_dap_datum_mempool_gdb_group)) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);
        // add transaction to utxo
        if(dap_chain_utxo_tx_add((dap_chain_datum_tx_t*) l_datum->data)<0)
            log_it(L_ERROR, "Transaction %s not placed in UTXO", l_key_str);
    }
    DAP_DELETE(l_key_str);

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
        datum_mempool->data[i];
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
    dap_hash((char*) datum_str, datum_size, a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_SLOW_0);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL;
    }
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
    dap_enc_key_t *key = dap_enc_ks_find_http(cl_st->http);
    //dap_enc_key_serealize_t *key_ser = dap_enc_key_serealize(key_tmp);
    //dap_enc_key_t *key = dap_enc_key_deserealize(key_ser, sizeof(dap_enc_key_serealize_t));

    // read header
    dap_http_header_t *hdr_session_close_id =
            (cl_st->http) ? dap_http_header_find(cl_st->http->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http) ? dap_http_header_find(cl_st->http->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);
    if(dg) {
        char *suburl = dg->url_path;
        char *request_str = dg->request_str;
        int request_size = dg->request_size;
        printf("!!***!!! chain_mempool_proc arg=%d suburl=%s str=%s len=%d\n", arg, suburl, request_str, request_size);
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
                            dap_datum_mempool_deserialize(request_str, (size_t) request_size) : NULL;
            if(datum_mempool)
            {
                dap_datum_mempool_free(datum_mempool);
                char *a_key = calc_datum_hash(request_str, (size_t) request_size);
                char *a_value;
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD: // add datum in base
                    //a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                    //bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                    if(dap_chain_global_db_gr_set(a_key, request_str, request_size,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        *return_code = Http_Status_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == Http_Status_OK) ? "OK" : "False!");
                    //DAP_DELETE(a_value);
                    break;

                case DAP_DATUM_MEMPOOL_CHECK: // check datum in base

                    strcpy(cl_st->reply_mime, "text/text");
                    char *str = dap_chain_global_db_gr_get((const char*) a_key, NULL,
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
                    if(dap_chain_global_db_gr_del(((const char*) a_key),
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        dg->response = strdup("1");
                        DAP_DELETE(str);
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
