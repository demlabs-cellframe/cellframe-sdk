#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_list.h>
#include <dap_string.h>
#include <dap_hash.h>
#include "dap_chain_datum_tx_items.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_hist.h"

#include "uthash.h"
// for dap_db_history_filter()
typedef struct dap_tx_data{
        dap_chain_hash_fast_t tx_hash;
        char token_ticker[10];
        size_t obj_num;
        size_t pos_num;
        dap_chain_addr_t addr;
        UT_hash_handle hh;
} dap_tx_data_t;

#define LOG_TAG "dap_chain_global_db_hist"

static char* dap_db_history_pack_hist(dap_global_db_hist_t *a_rec)
{
    char *l_ret = dap_strdup_printf("%c%s%u%s%s%s%s", a_rec->type, GLOBAL_DB_HIST_REC_SEPARATOR, a_rec->keys_count,
    GLOBAL_DB_HIST_REC_SEPARATOR, a_rec->group, GLOBAL_DB_HIST_REC_SEPARATOR, a_rec->keys);
    return l_ret;
}

static int dap_db_history_unpack_hist(char *l_str_in, dap_global_db_hist_t *a_rec_out)
{
    char **l_strv = dap_strsplit(l_str_in, GLOBAL_DB_HIST_REC_SEPARATOR, -1);
    size_t l_count = dap_str_countv(l_strv);
    if(l_count != 4)
        return -1;
    a_rec_out->type = l_strv[0][0];
    a_rec_out->keys_count = strtoul(l_strv[1], NULL, 10);
    a_rec_out->group = dap_strdup(l_strv[2]);
    a_rec_out->keys = dap_strdup(l_strv[3]);
    dap_strfreev(l_strv);
    return 1;
}

static char* dap_db_new_history_timestamp()
{
    static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
    // get unique key
    pthread_mutex_lock(&s_mutex);
    static time_t s_last_time = 0;
    static uint64_t s_suffix = 0;
    time_t l_cur_time = time(NULL);
    if(s_last_time == l_cur_time)
        s_suffix++;
    else {
        s_suffix = 0;
        s_last_time = l_cur_time;
    }
    char *l_str = dap_strdup_printf("%lld_%lld", (uint64_t) l_cur_time, s_suffix);
    pthread_mutex_unlock(&s_mutex);
    return l_str;
}

/**
 * Get data according the history log
 *
 * return dap_store_obj_pkt_t*
 */
uint8_t* dap_db_log_pack(dap_global_db_obj_t *a_obj, size_t *a_data_size_out)
{
    if(!a_obj)
        return NULL;
    dap_global_db_hist_t l_rec;
    if(dap_db_history_unpack_hist((char*) a_obj->value, &l_rec) == -1)
        return NULL;
    time_t l_timestamp = strtoll(a_obj->key, NULL, 10);

    // parse global_db records in a history record
    char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
    size_t l_count = dap_str_countv(l_keys);
    // read records from global_db
    int i = 0;
    dap_store_obj_t *l_store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count * sizeof(dap_store_obj_t));
    while(l_keys[i]) {
        dap_store_obj_t *l_obj = NULL;
        // add record - read record
        if(l_rec.type == 'a'){
            l_obj = (dap_store_obj_t*) dap_chain_global_db_obj_get(l_keys[i], l_rec.group);
            // l_obj may be NULL, if this record has been deleted but it is present in history
            if(l_obj)
                l_obj->id = a_obj->id;
        }
        // delete record - save only key for record
        else if(l_rec.type == 'd') { // //section=strdup("kelvin_nodes");
            l_obj = (dap_store_obj_t*) DAP_NEW_Z(dap_store_obj_t);
            l_obj->id = a_obj->id;
            l_obj->group = dap_strdup(l_rec.group);
            l_obj->key = dap_strdup(l_keys[i]);
        }
        if(l_obj == NULL) {
            dap_store_obj_free(l_store_obj, l_count);
            dap_strfreev(l_keys);
            return NULL;
        }
        // save record type: 'a' or 'd'
        l_obj->type = l_rec.type;

        memcpy(l_store_obj + i, l_obj, sizeof(dap_store_obj_t));
        DAP_DELETE(l_obj);
        i++;
    };
    // serialize data
    dap_store_obj_pkt_t *l_data_out = dap_store_packet_multiple(l_store_obj, l_timestamp, l_count);

    dap_store_obj_free(l_store_obj, l_count);
    dap_strfreev(l_keys);

    if(l_data_out && a_data_size_out) {
        *a_data_size_out = sizeof(dap_store_obj_pkt_t) + l_data_out->data_size;
    }
    return (uint8_t*) l_data_out;

}


// for dap_db_history_filter()
static dap_store_obj_t* get_prev_tx(dap_global_db_obj_t *a_objs, dap_tx_data_t *a_tx_data)
{
    if(!a_objs || !a_tx_data)
        return NULL;
    dap_global_db_obj_t *l_obj_cur = a_objs + a_tx_data->obj_num;
    dap_global_db_hist_t l_rec;
    if(dap_db_history_unpack_hist((char*) l_obj_cur->value, &l_rec) == -1)
        return NULL;
    char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
    size_t l_count = dap_str_countv(l_keys);
    if(a_tx_data->pos_num >= l_count) {
        dap_strfreev(l_keys);
        return NULL;
    }
    dap_store_obj_t *l_obj =
            (dap_store_obj_t*) l_keys ? dap_chain_global_db_obj_get(l_keys[a_tx_data->pos_num], l_rec.group) : NULL;
    dap_strfreev(l_keys);
    return l_obj;
}

/**
 * Get data according the history log
 *
 * return dap_store_obj_pkt_t*
 */
char* dap_db_history_filter(dap_chain_addr_t * a_addr, size_t *a_data_size_out)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    // load history
    size_t l_data_size_out = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    size_t i, j;
    //dap_list_t *l_hash_out_list = NULL;
    dap_tx_data_t *l_tx_data_hash = NULL;
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs + i;

        // parse global_db records in a history record
        dap_global_db_hist_t l_rec;
        if(dap_db_history_unpack_hist((char*) l_obj_cur->value, &l_rec) == -1)
            continue;
        char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
        size_t l_count = dap_str_countv(l_keys);
        dap_store_obj_t *l_obj = NULL;
        // all objs in one history records
        for(j = 0; j < l_count; j++) {
            // selection the groups with datums
            // todo

            // add record
            if(l_rec.type == 'a') {
                l_obj = (dap_store_obj_t*) dap_chain_global_db_obj_get(l_keys[j], l_rec.group);
                if(!l_obj)
                    continue;
                dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_obj->value;
                if(!l_datum)
                    continue;
                switch (l_datum->header.type_id) {
                /*                case DAP_CHAIN_DATUM_TOKEN_DECL: {
                 dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
                 dap_chain_ledger_token_add(a_chain->ledger, l_token, l_datum->header.data_size);
                 }
                 break;
                 case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                 dap_chain_datum_token_emission_t *l_token_emission =
                 (dap_chain_datum_token_emission_t*) l_datum->data;
                 dap_chain_ledger_token_emission_add(a_chain->ledger, l_token_emission, l_datum->header.data_size);
                 }
                 break;*/
                // find transaction
                case DAP_CHAIN_DATUM_TX: {
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
                    dap_list_t *l_records_out = NULL;
                    /*{
                        dap_chain_hash_fast_t l_tx_hash;
                        dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                        printf("*tx time=%lld tx_hash=%s\n",l_tx->header.ts_created, dap_chain_hash_fast_to_str_new(&l_tx_hash));
                    }*/

                    //dap_chain_hash_fast_t l_hash1;
                    //dap_hash_fast(l_datum, dap_chain_datum_size(l_tx), &l_hash1);
                    //printf("*tx time=%lld da_hash=%s\n",l_tx->header.ts_created, dap_chain_hash_fast_to_str_new(&l_hash1));

                    int l_count = 0;
                    dap_tx_data_t *l_tx_data = NULL;
                    dap_string_append_printf(l_str_out, "*tx start time=%lld\n",l_tx->header.ts_created);
                    // find Token items
                    l_count = 0;
                    dap_list_t *l_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, &l_count);

                    // find OUT items
                    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, &l_count);
                    dap_list_t *l_list_tmp = l_list_out_items;
                    while(l_list_tmp) {
                        const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                        //find a_addr
                        //if(memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                        {
                            // save tx hash
                            l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                            dap_chain_hash_fast_t l_tx_hash;
                            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                            memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                            memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                            l_tx_data->obj_num = i;
                            l_tx_data->pos_num = j;
                            // save token
                            if(l_tx_data && l_tx_token) {
                                dap_chain_tx_token_t *tk = l_tx_token->data;
                                int d = sizeof(l_tx_data->token_ticker);
                                memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                            }
                            HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);

                            //dap_string_append_printf(l_str_out, "*out cur val=%lld addr=%s\n",l_tx_out->header.value, dap_chain_addr_to_str(&l_tx_out->addr));
                            // added incoming values
                            // filter addr
                            if(!memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {
                                // save OUT item
                                //dap_tx_data_t *l_tx_data_new = DAP_NEW_Z(dap_tx_data_t);
                                //memcpy(l_tx_data_new, l_tx_data);
                                l_records_out = dap_list_append(l_records_out, l_tx_out);

                                //char *l_addr_to_str = dap_chain_addr_to_str(&l_tx_out->addr);
                                //dap_string_append_printf(l_str_out, "recv %lld %s\n", l_tx_out->header.value,
                                        //l_tx_data->token_ticker);
                                //DAP_DELETE(l_addr_to_str);
                            }
                        }
                        l_list_tmp = dap_list_next(l_list_tmp);
                    }

                    // find IN items
                    l_count = 0;
                    dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, &l_count);
                    l_list_tmp = l_list_in_items;
                    while(l_list_tmp) {
                        const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                        dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                        // if first transaction
                        if(dap_hash_fast_is_blank(&tx_prev_hash)) {
                            // print OUT records
                            dap_list_t *l_records_tmp = l_records_out;
                            while(l_records_tmp) {
                                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;
                                dap_string_append_printf(l_str_out, "%lld recv %lld %s\n",
                                        l_tx->header.ts_created,
                                        l_tx_out->header.value,
                                        l_tx_data->token_ticker);
                                l_records_tmp = dap_list_next(l_records_tmp);
                            }
                            dap_list_free(l_records_out);
                        }
                        else {
                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                // added token in cur OUT from prev OUT
                                dap_list_t *l_records_tmp = l_records_out;
                                while(l_records_tmp) {
                                    //dap_tx_data_t *l_tx_data_cur = (dap_tx_data_t*) l_records_tmp->data;
                                    //if(l_tx_data_cur)
                                      //  memcpy(l_tx_data_cur->token_ticker, l_tx_data_prev->token_ticker,
                                        //        sizeof(l_tx_data->token_ticker));



                                    const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;
                                    //char *l_addr_to_str = dap_chain_addr_to_str(&l_tx_out->addr);

                                    char *l_addr_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) : NULL;

                                    dap_string_append_printf(l_str_out, "%lld recv %lld %s to %s\n",
                                            l_tx->header.ts_created,
                                            l_tx_out->header.value,
                                            l_tx_data_prev->token_ticker,
                                            l_addr_str ? l_addr_str : "");
                                    DAP_DELETE(l_addr_str);
                                    //DAP_DELETE(l_addr_to_str);
                                    l_records_tmp = dap_list_next(l_records_tmp);
                                }
                                dap_list_free(l_records_out);

                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));

                                    dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data);
                                    dap_chain_datum_t *l_datum_prev =
                                            l_obj_prev ? (dap_chain_datum_t*) l_obj_prev->value : NULL;
                                    dap_chain_datum_tx_t *l_tx_prev =
                                            l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                                    // find OUT items in prev datum
                                    dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                            TX_ITEM_TYPE_OUT, &l_count);
                                    // find OUT item for IN item;
                                    dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                            l_tx_in->header.tx_out_prev_idx);
                                    dap_chain_tx_out_t *l_tx_prev_out =
                                            l_list_out_prev_item ?
                                                    (dap_chain_tx_out_t*) l_list_out_prev_item->data : NULL;
                                    //dap_string_append_printf(l_str_out, "*in prv val=%lld addr=%s\n",l_tx_prev_out->header.value, dap_chain_addr_to_str(&l_tx_prev_out->addr));

                                    // find source addrs
                                    dap_string_t *l_src_addr = dap_string_new(NULL);
                                    {
                                        // find IN items in prev datum - for get destination addr
                                        dap_list_t *l_list_in_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                                TX_ITEM_TYPE_IN, &l_count);
                                        dap_list_t *l_list_tmp = l_list_in_prev_items;
                                        while(l_list_tmp) {
                                            dap_chain_tx_in_t *l_tx_prev_in = l_list_tmp->data;
                                            dap_chain_hash_fast_t l_tx_prev_prev_hash =
                                                    l_tx_prev_in->header.tx_prev_hash;
                                            //find prev OUT item
                                            dap_tx_data_t *l_tx_data_prev_prev = NULL;
                                            HASH_FIND(hh, l_tx_data_hash, &l_tx_prev_prev_hash,
                                                    sizeof(dap_chain_hash_fast_t), l_tx_data_prev_prev);
                                            if(l_tx_data_prev_prev) {
                                                char *l_str = dap_chain_addr_to_str(&l_tx_data_prev_prev->addr);
                                                dap_string_append_printf(l_src_addr, "\n  %s", l_str);
                                                DAP_DELETE(l_str);
                                                //l_src_addr = dap_list_append(l_src_addr, &l_tx_data_prev_prev->addr);
                                            }
                                            l_list_tmp = dap_list_next(l_list_tmp);
                                        }
                                    }

                                    char *l_dst_to_str =
                                            (l_tx_prev_out) ? dap_chain_addr_to_str(&l_tx_prev_out->addr) :
                                            NULL;

                                    dap_string_append_printf(l_str_out, "%lld send %lld %s from %s\n to %s\n",
                                            l_tx->header.ts_created,
                                            l_tx_prev_out->header.value,
                                            l_tx_data->token_ticker,
                                            dap_string_free(l_src_addr, false),
                                            l_dst_to_str);
                                    DAP_DELETE(l_dst_to_str);
                                    // filter addr
                                    //if(l_tx_prev_out && !memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                    {
                                        char *l_addr_to_str =
                                                (l_tx_prev_out) ? dap_chain_addr_to_str(&l_tx_prev_out->addr) :
                                                NULL;
                                        // added outcoming values
//                                        dap_string_append_printf(l_str_out, "send %lld %s to addr %s\n",
//                                                l_tx_prev_out->header.value,
//                                                l_tx_data->token_ticker, l_addr_to_str);
                                        DAP_DELETE(l_addr_to_str);
                                    }

                                    dap_list_free(l_list_out_prev_items);
                                    DAP_DELETE(l_obj_prev);
                                }
                            }
                        }
                        l_list_tmp = dap_list_next(l_list_tmp);
                    }
                    if(l_list_out_items)
                        dap_list_free(l_list_out_items);
                    if(l_list_in_items)
                        dap_list_free(l_list_in_items);
                }
                    break;
                default:
                    continue;
                }
            }
            // delete record - save only key for record
            else if(l_rec.type == 'd') { // //section=strdup("kelvin_nodes");
                //printf("del_gr%d_%d=%s\n", i, j, l_rec.group);
                l_obj = (dap_store_obj_t*) DAP_NEW_Z(dap_store_obj_t);
                l_obj->group = dap_strdup(l_rec.group);
                l_obj->key = dap_strdup(l_keys[j]);
            }
        }
        DAP_DELETE(l_obj);
        dap_strfreev(l_keys);
    }
    // delete hashes
    dap_tx_data_t *l_iter_current, *l_item_tmp;
    HASH_ITER(hh, l_tx_data_hash , l_iter_current, l_item_tmp)
    {
        // delete struct
        DAP_DELETE(l_iter_current);
        HASH_DEL(l_tx_data_hash, l_iter_current);
    }
//    dap_list_free_full(l_hash_out_list, free);

    if(a_data_size_out)
        *a_data_size_out = l_data_size_out;
    // last element - NULL (marker)
    //l_keys_vals[l_data_size_out * 2] = NULL;
    //char *l_keys_vals_flat = dap_strjoinv(GLOBAL_DB_HIST_KEY_SEPARATOR, l_keys_vals0);
    //DAP_DELETE(l_keys_vals0[0]);
    //DAP_DELETE(l_keys_vals0);
    //dap_strfreev(l_keys_vals0);
    dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;

    return l_ret_str;

}

/**
 * Add data to the history log
 */
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, size_t a_dap_store_count)
{
    if(!a_store_obj || a_dap_store_count <= 0)
        return false;
    dap_global_db_hist_t l_rec;
    l_rec.keys_count = a_dap_store_count;
    l_rec.type = a_type;
    // group name should be always the same
    if(l_rec.keys_count >= 1)
        l_rec.group = a_store_obj->group;
    if(l_rec.keys_count == 1)
        l_rec.keys = a_store_obj->key;
    else {
        // make keys vector
        char **l_keys = DAP_NEW_Z_SIZE(char*, sizeof(char*) * (((size_t ) a_dap_store_count) + 1));
        size_t i;
        for(i = 0; i < a_dap_store_count; i++) {
            // if it is marked, the data has not been saved
            if(a_store_obj[i].timestamp == (time_t) -1)
                continue;
            l_keys[i] = a_store_obj[i].key;
        }
        l_keys[i] = NULL;
        l_rec.keys = dap_strjoinv(GLOBAL_DB_HIST_KEY_SEPARATOR, l_keys);
        DAP_DELETE(l_keys);
    }

    char *l_str = dap_db_history_pack_hist(&l_rec);
    size_t l_str_len = strlen(l_str);
    dap_store_obj_t l_store_data;
    // key - timestamp
    // value - keys of added/deleted data
    l_store_data.key = dap_db_new_history_timestamp();
    l_store_data.value = (uint8_t*) strdup(l_str);
    l_store_data.value_len = l_str_len + 1;
    l_store_data.group = GROUP_LOCAL_HISTORY;
    l_store_data.timestamp = time(NULL);
    int l_res = dap_chain_global_db_driver_add(&l_store_data, 1);
    if(l_rec.keys_count > 1)
        DAP_DELETE(l_rec.keys);
    DAP_DELETE(l_str);
    if(!l_res)
        return true;
    return false;
}

/**
 * Truncate the history log
 */
bool dap_db_history_truncate(void)
{
    // TODO
    return true;
}

/**
 * Get last timestamp in log
 */
uint64_t dap_db_log_get_last_id(void)
{
    //dap_store_obj_t *l_last_obj = dap_chain_global_db_driver_read_last(
    dap_store_obj_t *l_last_obj = dap_chain_global_db_get_last(GROUP_LOCAL_HISTORY);
    if(l_last_obj) {
        return l_last_obj->id;
    }
    /*    char *last_key = NULL;
     size_t l_data_size_out = 0;
     dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
     if(l_data_size_out > 0)
     last_key = l_objs[0]->key;
     for(size_t i = 1; i < l_data_size_out; i++) {
     dap_global_db_obj_t *l_obj_cur = l_objs[i];
     if(strcmp(last_key, l_obj_cur->key) < 0) {
     last_key = l_obj_cur->key;
     //printf("l_obj_cur->key=%s last_key\n", l_obj_cur->key);
     }
     //printf("l_obj_cur->key=%s\n", l_obj_cur->key);
     }
     time_t l_ret_time = last_key? strtoll(last_key, NULL, 10): 0;
     dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
     return l_ret_time;*/
}

/*static int compare_items(const void * l_a, const void * l_b)
{
    const dap_global_db_obj_t *l_item_a = (const dap_global_db_obj_t*) l_a;
    const dap_global_db_obj_t *l_item_b = (const dap_global_db_obj_t*) l_b;
    int l_ret = strcmp(l_item_a->key, l_item_b->key);
    return l_ret;
}*/

/**
 * Get log diff as list
 */
dap_list_t* dap_db_log_get_list(uint64_t first_id)
{
    dap_list_t *l_list = NULL;
    size_t l_data_size_out = 0;
    dap_store_obj_t *l_objs = dap_chain_global_db_cond_load(GROUP_LOCAL_HISTORY, first_id, &l_data_size_out);
    //dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, first_timestamp, &l_data_size_out);
    for(size_t i = 0; i < l_data_size_out; i++) {
        dap_store_obj_t *l_obj_cur = l_objs + i;
        dap_global_db_obj_t *l_item = DAP_NEW(dap_global_db_obj_t);
        l_item->id = l_obj_cur->id;
        l_item->key = dap_strdup(l_obj_cur->key);
        l_item->value = (uint8_t*) dap_strdup((char*) l_obj_cur->value);
        l_list = dap_list_append(l_list, l_item);
    }
    dap_store_obj_free(l_objs, l_data_size_out);

    return l_list;
    /*
     size_t l_list_count = 0;
     char *l_first_key_str = dap_strdup_printf("%lld", (int64_t) first_timestamp);
     size_t l_data_size_out = 0;

     for(size_t i = 0; i < l_data_size_out; i++) {
     dap_global_db_obj_t *l_obj_cur = l_objs[i];
     //        log_it(L_DEBUG,"%lld and %lld tr",strtoll(l_obj_cur->key,NULL,10), first_timestamp );
     if( strtoll(l_obj_cur->key,NULL,10) > (long long) first_timestamp  ) {
     dap_global_db_obj_t *l_item = DAP_NEW(dap_global_db_obj_t);
     l_item->key = dap_strdup(l_obj_cur->key);
     l_item->value =(uint8_t*) dap_strdup((char*) l_obj_cur->value);
     l_list = dap_list_append(l_list, l_item);
     l_list_count++;
     }
     }
     // sort list by key (time str)
     //dap_list_sort(l_list, (dap_callback_compare_t) compare_items);
     log_it(L_DEBUG,"Prepared %u items (list size %u)", l_list_count, dap_list_length(l_list));
     DAP_DELETE(l_first_key_str);
     dap_chain_global_db_objs_delete(l_objs);
     */
    /*/ dbg - sort result
     l_data_size_out = dap_list_length(l_list);
     for(size_t i = 0; i < l_data_size_out; i++) {
     dap_list_t *l_list_tmp = dap_list_nth(l_list, i);
     dap_global_db_obj_t *l_item = l_list_tmp->data;
     printf("2 %d %s\n", i, l_item->key);
     }*/

}

/**
 * Free list getting from dap_db_log_get_list()
 */
void dap_db_log_del_list(dap_list_t *a_list)
{
    dap_list_free_full(a_list, (dap_callback_destroyed_t) dap_chain_global_db_obj_delete);
}
