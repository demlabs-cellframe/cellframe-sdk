#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_string.h>
#include <dap_hash.h>
#include "dap_chain_datum_tx_items.h"

#include "dap_chain_global_db_hist.h"

#include "uthash.h"
// for dap_db_history()
typedef struct dap_tx_data{
        dap_chain_hash_fast_t tx_hash;
        char tx_hash_str[70];
        char token_ticker[10];
        size_t obj_num;
        size_t pos_num;
        dap_chain_addr_t addr;
        char reserv[3];
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
    uint64_t l_suffix = 0;
    time_t l_cur_time;
    // get unique key
    pthread_mutex_lock(&s_mutex);
    static time_t s_last_time = 0;
    static uint64_t s_suffix = 0;
    time_t l_cur_time_tmp = time(NULL);
    if(s_last_time == l_cur_time_tmp)
        s_suffix++;
    else {
        s_suffix = 0;
        s_last_time = l_cur_time_tmp;
    }
    // save tmp values
    l_cur_time = l_cur_time_tmp;
    l_suffix = s_suffix;
    pthread_mutex_unlock(&s_mutex);

    char *l_str = dap_strdup_printf("%lld_%lld", (uint64_t) l_cur_time, l_suffix);
    return l_str;
}

/**
 * Get data according the history log
 *
 * return dap_store_obj_pkt_t*
 */
dap_list_t* dap_db_log_pack(dap_global_db_obj_t *a_obj, size_t *a_data_size_out)
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
            l_obj->timestamp = global_db_gr_del_get_timestamp(l_obj->group, l_obj->key);
        }
        if(l_obj == NULL) {
            dap_store_obj_free(l_store_obj, l_count);
            dap_strfreev(l_keys);
            return NULL;
        }
        // save record type: 'a' or 'd'
        l_obj->type = (uint8_t)l_rec.type;

        memcpy(l_store_obj + i, l_obj, sizeof(dap_store_obj_t));
        DAP_DELETE(l_obj);
        i++;
    }
    // serialize data
    dap_list_t *l_data_out = dap_store_packet_multiple(l_store_obj, l_timestamp, l_count);

    dap_store_obj_free(l_store_obj, l_count);
    dap_strfreev(l_keys);

    if(l_data_out && a_data_size_out) {
        *a_data_size_out = 0;
        for (dap_list_t *l_iter = l_data_out; l_iter; l_iter = dap_list_next(l_iter)) {
            *a_data_size_out += sizeof(dap_store_obj_pkt_t) + ((dap_store_obj_pkt_t *)l_data_out)->data_size;
        }
    }
    return l_data_out;

}


// for dap_db_history()
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
 * return history string
 */
#if 0
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, const char *a_group_mempool)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    // load history
    size_t l_data_size_out = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    size_t i, j;
    bool l_tx_hash_found = false;
    dap_tx_data_t *l_tx_data_hash = NULL;
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs + i;

        // parse global_db records in a history record
        dap_global_db_hist_t l_rec;
        if(dap_db_history_unpack_hist((char*) l_obj_cur->value, &l_rec) == -1)
            continue;
        // use only groups with datums
        if(dap_strcmp(a_group_mempool, l_rec.group))
            continue;

        char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
        size_t l_count = dap_str_countv(l_keys);
        dap_store_obj_t *l_obj = NULL;
        // all objs in one history records
        for(j = 0; j < l_count; j++) {

            if(l_rec.type != 'a')
                continue;
            l_obj = (dap_store_obj_t*) dap_chain_global_db_obj_get(l_keys[j], l_rec.group);
            if(!l_obj)
                continue;
            // datum
            dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_obj->value;
            if(!l_datum && l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                continue;

            dap_tx_data_t *l_tx_data = NULL;

            // transaction
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;

            // find Token items - present in emit transaction
            dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);

            // find OUT items
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
            dap_list_t *l_list_tmp = l_list_out_items;
            while(l_list_tmp) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                // save OUT item l_tx_out
                if(!l_tx_data)
                {
                    // save tx hash
                    l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                    dap_chain_hash_fast_t l_tx_hash;
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                    memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                    dap_chain_hash_fast_to_str(&l_tx_data->tx_hash, l_tx_data->tx_hash_str,
                            sizeof(l_tx_data->tx_hash_str));
                    l_tx_data->obj_num = i;
                    l_tx_data->pos_num = j;
                    // save token name
                    if(l_list_tx_token) {
                        dap_chain_tx_token_t *tk = l_list_tx_token->data;
                        int d = sizeof(l_tx_data->token_ticker);
                        memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                    }
                    // take token from prev out item
                    else {

                        // find IN items
                        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
                        dap_list_t *l_list_tmp_in = l_list_in_items;
                        // find token_ticker in prev OUT items
                        while(l_list_tmp_in) {
                            const dap_chain_tx_in_t *l_tx_in =
                                    (const dap_chain_tx_in_t*) l_list_tmp_in->data;
                            dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;

                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t),
                                    l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                // fill token in l_tx_data from prev transaction
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));
                                    break;
                                }
                                l_list_tmp_in = dap_list_next(l_list_tmp_in);
                            }
                        }
                        if(l_list_in_items)
                            dap_list_free(l_list_in_items);
                    }
                    HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);
                }
                l_list_tmp = dap_list_next(l_list_tmp);
            }
            if(l_list_out_items)
                dap_list_free(l_list_out_items);

            // calc hash
            dap_chain_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
            // search tx with a_tx_hash
            if(!dap_hash_fast_compare(a_tx_hash, &l_tx_hash))
                continue;
            // found a_tx_hash now

            // transaction time
            char *l_time_str = NULL;
            if(l_tx->header.ts_created > 0) {
                time_t rawtime = (time_t) l_tx->header.ts_created;
                struct tm * timeinfo;
                timeinfo = localtime(&rawtime);
                if(timeinfo) {
                    dap_string_append_printf(l_str_out, " %s", asctime(timeinfo));
                }
            }

            // find all OUT items in transaction
            l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
            l_list_tmp = l_list_out_items;
            while(l_list_tmp) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                dap_tx_data_t *l_tx_data_prev = NULL;

                const char *l_token_str = NULL;
                if(l_tx_data)
                    l_token_str = l_tx_data->token_ticker;
                char *l_dst_to_str =
                        (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) :
                        NULL;
                dap_string_append_printf(l_str_out, " OUT item %lld %s to %s\n",
                        l_tx_out->header.value,
                        dap_strlen(l_token_str) > 0 ? l_token_str : "?",
                        l_dst_to_str ? l_dst_to_str : "?"
                                       );
                DAP_DELETE(l_dst_to_str);
                l_list_tmp = dap_list_next(l_list_tmp);
            }
            // find all IN items in transaction
            dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
            l_list_tmp = l_list_in_items;
            // find cur addr in prev OUT items
            while(l_list_tmp) {
                const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                char l_tx_hash_str[70];
                if(!dap_hash_fast_is_blank(&tx_prev_hash))
                    dap_chain_hash_fast_to_str(&tx_prev_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
                else
                    strcpy(l_tx_hash_str,"Null");
                dap_string_append_printf(l_str_out, " IN item \n  prev tx_hash %s\n", l_tx_hash_str);

                //find prev OUT item
                dap_tx_data_t *l_tx_data_prev = NULL;
                HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                if(l_tx_data_prev != NULL) {

                    dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data_prev);
                    dap_chain_datum_t *l_datum_prev =
                            l_obj_prev ? (dap_chain_datum_t*) l_obj_prev->value : NULL;
                    dap_chain_datum_tx_t *l_tx_prev =
                            l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                    // find OUT items in prev datum
                    dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                            TX_ITEM_TYPE_OUT, NULL);
                    // find OUT item for IN item;
                    dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                            l_tx_in->header.tx_out_prev_idx);
                    dap_chain_tx_out_t *l_tx_prev_out =
                            l_list_out_prev_item ?
                                                   (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                   NULL;
                    // print value from prev out item
                    dap_string_append_printf(l_str_out, "  prev OUT item value=%lld",
                            l_tx_prev_out->header.value
                            );
                }
                dap_string_append_printf(l_str_out, "\n");
                l_list_tmp = dap_list_next(l_list_tmp);
            }

            if(l_list_tx_token)
                dap_list_free(l_list_tx_token);
            if(l_list_out_items)
                dap_list_free(l_list_out_items);
            if(l_list_in_items)
                dap_list_free(l_list_in_items);
            l_tx_hash_found = true;
            break;
        }
        dap_list_t *l_records_out = NULL;

        DAP_DELETE(l_obj);
        dap_strfreev(l_keys);
        // transaction was found -> exit
        if(l_tx_hash_found)
            break;
    }
    dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}
#endif

/**
 * Get data according the history log
 *
 * return history string
 */
#if 0
char* dap_db_history_addr(dap_chain_addr_t * a_addr, const char *a_group_mempool)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    // load history
    size_t l_data_size_out = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    size_t i, j;
    dap_tx_data_t *l_tx_data_hash = NULL;
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs + i;
        // parse global_db records in a history record
        dap_global_db_hist_t l_rec;
        if(dap_db_history_unpack_hist((char*) l_obj_cur->value, &l_rec) == -1)
            continue;
        // use only groups with datums
        if(dap_strcmp(a_group_mempool, l_rec.group))
            continue;

        char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
        size_t l_count = dap_str_countv(l_keys);
        dap_store_obj_t *l_obj = NULL;
        // all objs in one history records
        for(j = 0; j < l_count; j++) {
            if(l_rec.type != 'a')
                continue;
            l_obj = (dap_store_obj_t*) dap_chain_global_db_obj_get(l_keys[j], l_rec.group);
            if(!l_obj)
                continue;
            // datum
            dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_obj->value;
            if(!l_datum && l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                continue;

            // transaction
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
            dap_list_t *l_records_out = NULL;
            // transaction time
            char *l_time_str = NULL;
            {
                if(l_tx->header.ts_created > 0) {
                    time_t rawtime = (time_t) l_tx->header.ts_created;
                    struct tm * timeinfo;
                    timeinfo = localtime(&rawtime);
                    if(timeinfo)
                        l_time_str = dap_strdup(asctime(timeinfo));
                }
                else
                    l_time_str = dap_strdup(" ");
            }

            // transaction
            dap_tx_data_t *l_tx_data = NULL;

            // find Token items - present in emit transaction
            dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);

            // find OUT items
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
            dap_list_t *l_list_tmp = l_list_out_items;
            while(l_list_tmp) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                // save OUT item l_tx_out
                {
                    // save tx hash
                    l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                    dap_chain_hash_fast_t l_tx_hash;
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                    memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                    dap_chain_hash_fast_to_str(&l_tx_data->tx_hash, l_tx_data->tx_hash_str,
                                                                sizeof(l_tx_data->tx_hash_str));
                    l_tx_data->obj_num = i;
                    l_tx_data->pos_num = j;
                    // save token name
                    if(l_tx_data && l_list_tx_token) {
                        dap_chain_tx_token_t *tk = l_list_tx_token->data;
                        int d = sizeof(l_tx_data->token_ticker);
                        memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                    }
                    HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);

                    // save OUT items to list
                    {
                        l_records_out = dap_list_append(l_records_out, (void*) l_tx_out);
                    }
                }
                l_list_tmp = dap_list_next(l_list_tmp);
            }

            // find IN items
            l_count = 0;
            dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
            l_list_tmp = l_list_in_items;
            // find cur addr in prev OUT items
            bool l_is_use_all_cur_out = false;
            {
                while(l_list_tmp) {
                    const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                    dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;

                    //find prev OUT item
                    dap_tx_data_t *l_tx_data_prev = NULL;
                    HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                    if(l_tx_data_prev != NULL) {
                        // fill token in l_tx_data from prev transaction
                        if(l_tx_data) {
                            // get token from prev tx
                            memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                    sizeof(l_tx_data->token_ticker));
                            dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data_prev);
                            dap_chain_datum_t *l_datum_prev =
                                    l_obj_prev ? (dap_chain_datum_t*) l_obj_prev->value : NULL;
                            dap_chain_datum_tx_t *l_tx_prev =
                                    l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                            // find OUT items in prev datum
                            dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                    TX_ITEM_TYPE_OUT, NULL);
                            // find OUT item for IN item;
                            dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                    l_tx_in->header.tx_out_prev_idx);
                            dap_chain_tx_out_t *l_tx_prev_out =
                                    l_list_out_prev_item ?
                                                           (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                           NULL;
                            if(l_tx_prev_out && !memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                l_is_use_all_cur_out = true;

                        }
                    }

                    // find prev OUT items for IN items
                    l_list_tmp = l_list_in_items;
                    while(l_list_tmp) {
                        const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                        dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                        // if first transaction - empty prev OUT item
                        if(dap_hash_fast_is_blank(&tx_prev_hash)) {
                            // add emit info to ret string
                            if(!memcmp(&l_tx_data->addr, a_addr, sizeof(dap_chain_addr_t)))
                                    {
                                dap_list_t *l_records_tmp = l_records_out;
                                while(l_records_tmp) {

                                    const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;
                                    dap_string_append_printf(l_str_out, "tx hash %s \n emit %lld %s\n",
                                            l_tx_data->tx_hash_str,
                                            l_tx_out->header.value,
                                            l_tx_data->token_ticker);
                                    l_records_tmp = dap_list_next(l_records_tmp);
                                }
                            }
                            dap_list_free(l_records_out);
                        }
                        // in other transactions except first one
                        else {
                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                char *l_src_str = NULL;
                                bool l_src_str_is_cur = false;
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));

                                    dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data_prev);
                                    dap_chain_datum_t *l_datum_prev =
                                            l_obj_prev ? (dap_chain_datum_t*) l_obj_prev->value : NULL;
                                    dap_chain_datum_tx_t *l_tx_prev =
                                            l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                                    // find OUT items in prev datum
                                    dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                            TX_ITEM_TYPE_OUT, NULL);
                                    // find OUT item for IN item;
                                    dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                            l_tx_in->header.tx_out_prev_idx);
                                    dap_chain_tx_out_t *l_tx_prev_out =
                                            l_list_out_prev_item ?
                                                                   (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                                   NULL;
                                    // if use src addr
                                    bool l_is_use_src_addr = false;
                                    // find source addrs
                                    dap_string_t *l_src_addr = dap_string_new(NULL);
                                    {
                                        // find IN items in prev datum - for get destination addr
                                        dap_list_t *l_list_in_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                                TX_ITEM_TYPE_IN, NULL);
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
                                                // if use src addr
                                                if(!memcmp(&l_tx_data_prev_prev->addr, a_addr,
                                                        sizeof(dap_chain_addr_t)))
                                                    l_is_use_src_addr = true;
                                                char *l_str = dap_chain_addr_to_str(&l_tx_data_prev_prev->addr);
                                                if(l_src_addr->len > 0)
                                                    dap_string_append_printf(l_src_addr, "\n   %s", l_str);
                                                else
                                                    dap_string_append_printf(l_src_addr, "%s", l_str); // first record
                                                DAP_DELETE(l_str);
                                            }
                                            l_list_tmp = dap_list_next(l_list_tmp);
                                        }
                                    }

                                    char *l_dst_to_str =
                                            (l_tx_prev_out) ? dap_chain_addr_to_str(&l_tx_prev_out->addr) :
                                            NULL;
                                    // if use dst addr
                                    bool l_is_use_dst_addr = false;
                                    if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                        l_is_use_dst_addr = true;

                                    l_src_str_is_cur = l_is_use_src_addr;
                                    if(l_src_addr->len <= 1) {
                                        l_src_str =
                                                (l_tx_data) ? dap_chain_addr_to_str(&l_tx_data->addr) :
                                                NULL;
                                        if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                            l_src_str_is_cur = true;
                                        dap_string_free(l_src_addr, true);
                                    }
                                    else
                                        l_src_str = dap_string_free(l_src_addr, false);
                                    if(l_is_use_src_addr && !l_is_use_dst_addr) {
                                        dap_string_append_printf(l_str_out,
                                                "tx hash %s \n %s in send  %lld %s from %s\n to %s\n",
                                                l_tx_data->tx_hash_str,
                                                l_time_str ? l_time_str : "",
                                                l_tx_prev_out->header.value,
                                                l_tx_data->token_ticker,
                                                l_src_str ? l_src_str : "",
                                                l_dst_to_str);
                                    } else if(l_is_use_dst_addr && !l_is_use_src_addr) {
                                        if(!l_src_str_is_cur)
                                            dap_string_append_printf(l_str_out,
                                                    "tx hash %s \n %s in recv %lld %s from %s\n",
                                                    l_tx_data->tx_hash_str,
                                                    l_time_str ? l_time_str : "",
                                                    l_tx_prev_out->header.value,
                                                    l_tx_data->token_ticker,
                                                    l_src_str ? l_src_str : "");
                                    }

                                    DAP_DELETE(l_dst_to_str);
                                    dap_list_free(l_list_out_prev_items);
                                    DAP_DELETE(l_obj_prev);
                                }

                                // OUT items
                                dap_list_t *l_records_tmp = l_records_out;
                                while(l_records_tmp) {

                                    const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;

                                    if(l_is_use_all_cur_out
                                            || !memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {

                                        char *l_addr_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) : NULL;

                                        if(!memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {
                                            if(!l_src_str_is_cur)
                                                dap_string_append_printf(l_str_out, "tx hash %s \n %s recv %lld %s from %s\n",
                                                        l_tx_data->tx_hash_str,
                                                        l_time_str ? l_time_str : "",
                                                        l_tx_out->header.value,
                                                        l_tx_data_prev->token_ticker,
                                                        l_src_str ? l_src_str : "?");
                                        }
                                        else {
                                            dap_string_append_printf(l_str_out, "tx hash %s \n %s send %lld %s to %sd\n",
                                                    l_tx_data->tx_hash_str,
                                                    l_time_str ? l_time_str : "",
                                                    l_tx_out->header.value,
                                                    l_tx_data_prev->token_ticker,
                                                    l_addr_str ? l_addr_str : "");
                                        }
                                        DAP_DELETE(l_addr_str);
                                    }
                                    l_records_tmp = dap_list_next(l_records_tmp);
                                }
                                dap_list_free(l_records_out);
                                DAP_DELETE(l_src_str);

                            }
                        }
                        l_list_tmp = dap_list_next(l_list_tmp);
                    }
                    l_list_tmp = dap_list_next(l_list_tmp);
                }
            }



            if(l_list_tx_token)
                dap_list_free(l_list_tx_token);
            if(l_list_out_items)
                dap_list_free(l_list_out_items);
            if(l_list_in_items)
                dap_list_free(l_list_in_items);

            DAP_DELETE(l_time_str);
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
    dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, " empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}
#endif


/**
 * Get data according the history log
 *
 * return history string
 */
char* dap_db_history(dap_chain_addr_t * a_addr, const char *a_group_mempool)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    // load history
    size_t l_data_size_out = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    size_t i, j;
    dap_tx_data_t *l_tx_data_hash = NULL;
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs + i;

        // parse global_db records in a history record
        dap_global_db_hist_t l_rec;
        if(dap_db_history_unpack_hist((char*) l_obj_cur->value, &l_rec) == -1)
            continue;
        // use only groups with datums
        if(dap_strcmp(a_group_mempool, l_rec.group))
            continue;

        char **l_keys = dap_strsplit(l_rec.keys, GLOBAL_DB_HIST_KEY_SEPARATOR, -1);
        size_t l_count = dap_str_countv(l_keys);
        dap_store_obj_t *l_obj = NULL;
        // all objs in one history records
        for(j = 0; j < l_count; j++) {
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
                 }
                 break;
                 case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                 dap_chain_datum_token_emission_t *l_token_emission =
                 (dap_chain_datum_token_emission_t*) l_datum->data;
                 }
                 break;*/
                // find transaction
                case DAP_CHAIN_DATUM_TX: {
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
                    dap_list_t *l_records_out = NULL;

                    // transaction time
                    char *l_time_str = NULL;
                    if(l_tx->header.ts_created > 0) {
                        time_t rawtime = (time_t) l_tx->header.ts_created;
                        struct tm * timeinfo;
                        timeinfo = localtime(&rawtime);
                        if(timeinfo)
                            l_time_str = dap_strdup(asctime(timeinfo));
                    }
                    else
                        l_time_str = dap_strdup(" ");

                    int l_count = 0;
                    dap_tx_data_t *l_tx_data = NULL;
                    // find Token items - present in emit transaction
                    l_count = 0;
                    dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, &l_count);

                    // find OUT items
                    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, &l_count);
                    dap_list_t *l_list_tmp = l_list_out_items;
                    while(l_list_tmp) {
                        dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*) l_list_tmp->data;
                        // save OUT item l_tx_out
                        {
                            // save tx hash
                            l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                            dap_chain_hash_fast_t l_tx_hash;
                            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                            memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                            memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                            l_tx_data->obj_num = i;
                            l_tx_data->pos_num = j;
                            // save token name
                            if(l_tx_data && l_list_tx_token) {
                                dap_chain_tx_token_t *tk = l_list_tx_token->data;
//                                int d = sizeof(l_tx_data->token_ticker);
                                memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                            }
                            HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);

                            // save OUT items to list
                            {
                                l_records_out = dap_list_append(l_records_out, (void*) l_tx_out);
                            }
                        }
                        l_list_tmp = dap_list_next(l_list_tmp);
                    }

                    // find IN items
                    l_count = 0;
                    dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, &l_count);
                    l_list_tmp = l_list_in_items;

                    // find cur addr in prev OUT items
                    bool l_is_use_all_cur_out = false;
                    {
                        while(l_list_tmp) {
                            const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                            dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;

                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                // fill token in l_tx_data from prev transaction
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));
                                    dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data_prev);
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
                                                                   (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                                   NULL;
                                    if(l_tx_prev_out && !memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                        l_is_use_all_cur_out = true;

                                }
                            }
                            l_list_tmp = dap_list_next(l_list_tmp);
                        }
                    }

                    // find prev OUT items for IN items
                    l_list_tmp = l_list_in_items;
                    while(l_list_tmp) {
                        const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                        dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                        // if first transaction - empty prev OUT item
                        if(dap_hash_fast_is_blank(&tx_prev_hash)) {
                            // add emit info to ret string
                            if(l_tx_data && a_addr &&
                                    ( memcmp(&l_tx_data->addr, a_addr, sizeof(dap_chain_addr_t) ) == 0 )
                                ) {
                                dap_list_t *l_records_tmp = l_records_out;
                                while(l_records_tmp) {
                                    const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;
                                    dap_string_append_printf(l_str_out, "emit %lld %s\n",
                                            l_tx_out->header.value,
                                            l_tx_data->token_ticker);
                                    l_records_tmp = dap_list_next(l_records_tmp);
                                }
                            }
                            dap_list_free(l_records_out);
                        }
                        // in other transactions except first one
                        else {
                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                char *l_src_str = NULL;
                                bool l_src_str_is_cur = false;
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));

                                    dap_store_obj_t *l_obj_prev = get_prev_tx(l_objs, l_tx_data_prev);
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
                                                                   (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                                   NULL;
                                    // if use src addr
                                    bool l_is_use_src_addr = false;
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
                                                // if use src addr
                                                if(!memcmp(&l_tx_data_prev_prev->addr, a_addr,
                                                        sizeof(dap_chain_addr_t)))
                                                    l_is_use_src_addr = true;
                                                char *l_str = dap_chain_addr_to_str(&l_tx_data_prev_prev->addr);
                                                if(l_src_addr->len > 0)
                                                    dap_string_append_printf(l_src_addr, "\n   %s", l_str);
                                                else
                                                    dap_string_append_printf(l_src_addr, "%s", l_str); // first record
                                                DAP_DELETE(l_str);
                                            }
                                            l_list_tmp = dap_list_next(l_list_tmp);
                                        }
                                    }

                                    char *l_dst_to_str =
                                            (l_tx_prev_out) ? dap_chain_addr_to_str(&l_tx_prev_out->addr) :
                                            NULL;
                                    // if use dst addr
                                    bool l_is_use_dst_addr = false;
                                    if(l_tx_prev_out &&  a_addr &&
                                            ( memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t) ) == 0 )){
                                        l_is_use_dst_addr = true;
                                    }

                                    l_src_str_is_cur = l_is_use_src_addr;
                                    if(l_src_addr->len <= 1) {
                                        l_src_str =
                                                (l_tx_data) ? dap_chain_addr_to_str(&l_tx_data->addr) :
                                                NULL;
                                        if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                            l_src_str_is_cur = true;
                                        dap_string_free(l_src_addr, true);
                                    }
                                    else
                                        l_src_str = dap_string_free(l_src_addr, false);
                                    if(l_is_use_src_addr && !l_is_use_dst_addr) {
                                        dap_string_append_printf(l_str_out,
                                                "%s in send  %lld %s from %s\n to %s\n",
                                                l_time_str ? l_time_str : "",
                                                l_tx_prev_out?l_tx_prev_out->header.value:0,
                                                l_tx_data->token_ticker,
                                                l_src_str ? l_src_str : "",
                                                l_dst_to_str);
                                    } else if(l_is_use_dst_addr && !l_is_use_src_addr) {
                                        if(!l_src_str_is_cur)
                                            dap_string_append_printf(l_str_out,
                                                    "%s in recv %lld %s from %s\n",
                                                    l_time_str ? l_time_str : "",
                                                    l_tx_prev_out->header.value,
                                                    l_tx_data->token_ticker,
                                                    l_src_str ? l_src_str : "");
                                    }

                                    DAP_DELETE(l_dst_to_str);
                                    dap_list_free(l_list_out_prev_items);
                                    DAP_DELETE(l_obj_prev);
                                }

                                // OUT items
                                dap_list_t *l_records_tmp = l_records_out;
                                while(l_records_tmp) {

                                    const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;

                                    if(l_is_use_all_cur_out
                                            || !memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {

                                        char *l_addr_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) : NULL;

                                        if(!memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {
                                            if(!l_src_str_is_cur)
                                                dap_string_append_printf(l_str_out, "%s recv %lld %s from %s\n",
                                                        l_time_str ? l_time_str : "",
                                                        l_tx_out->header.value,
                                                        l_tx_data_prev->token_ticker,
                                                        l_src_str ? l_src_str : "?");
                                        }
                                        else {
                                            dap_string_append_printf(l_str_out, "%s send %lld %s to %sd\n",
                                                    l_time_str ? l_time_str : "",
                                                    l_tx_out->header.value,
                                                    l_tx_data_prev->token_ticker,
                                                    l_addr_str ? l_addr_str : "");
                                        }
                                        DAP_DELETE(l_addr_str);
                                    }
                                    l_records_tmp = dap_list_next(l_records_tmp);
                                }
                                dap_list_free(l_records_out);
                                DAP_DELETE(l_src_str);

                            }
                        }
                        l_list_tmp = dap_list_next(l_list_tmp);
                    }
                    if(l_list_tx_token)
                        dap_list_free(l_list_tx_token);
                    if(l_list_out_items)
                        dap_list_free(l_list_out_items);
                    if(l_list_in_items)
                        dap_list_free(l_list_in_items);

                    DAP_DELETE(l_time_str);
                }
                    break;
                default:
                    continue;
                }
            }
            // delete record
            else if(l_rec.type == 'd') {
                //printf("del_gr%d_%d=%s\n", i, j, l_rec.group);
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
    dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * Add data to the history log
 */
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, size_t a_dap_store_count, const char *a_group)
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
    l_store_data.value = (uint8_t*)l_str;
    l_store_data.value_len = l_str_len + 1;
    l_store_data.group = (char*)a_group;//GROUP_LOCAL_HISTORY;
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
 * Get last id in log
 */
uint64_t dap_db_log_get_group_history_last_id(const char *a_history_group_name)
{
    uint64_t result = 0;
    dap_store_obj_t *l_last_obj = dap_chain_global_db_get_last(a_history_group_name);
    if(l_last_obj) {
        result = l_last_obj->id;
        dap_store_obj_free(l_last_obj, 1);
    }
    return result;
}

/**
 * Get last id in log
 */
uint64_t dap_db_log_get_last_id(void)
{
    return dap_db_log_get_group_history_last_id(GROUP_LOCAL_HISTORY);
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
    //log_it(L_DEBUG,"loading db list...");
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
    //log_it(L_DEBUG,"loaded db list n=%d", l_data_size_out);
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




/**
 * Thread for reading log list
 * instead dap_db_log_get_list()
 */
static void *s_list_thread_proc(void *arg)
{
    dap_db_log_list_t *l_dap_db_log_list = (dap_db_log_list_t*) arg;
    size_t l_items_number = 0;
    while(1) {
        bool is_process;
        char *l_group_cur_name = NULL;
        // check for break process
        pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
        is_process = l_dap_db_log_list->is_process;
        size_t l_item_start = l_dap_db_log_list->item_start;
        size_t l_item_last = l_dap_db_log_list->item_last;
        if(l_dap_db_log_list->group_cur == -1)
            l_group_cur_name = GROUP_LOCAL_HISTORY;
        else
            l_group_cur_name = l_dap_db_log_list->group_names[l_dap_db_log_list->group_cur];
        pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
        if(!is_process)
            break;
        // calculating how many items required to read
        size_t l_item_count =(uint64_t) min(10, (int64_t)l_item_last - (int64_t)l_item_start + 1);
        dap_store_obj_t *l_objs = NULL;
        // read next 1...10 items
        if(l_item_count > 0)
            l_objs = dap_chain_global_db_cond_load(l_group_cur_name, l_item_start, &l_item_count);
        // go to next group
        if(!l_objs) {
            pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
            while(l_dap_db_log_list->group_cur < l_dap_db_log_list->group_number) {
                l_dap_db_log_list->group_cur++;
                // check for empty group
                if( !(l_dap_db_log_list->group_number) || (l_dap_db_log_list->group_number_items[l_dap_db_log_list->group_cur] < 1)) {
                    continue;
                }
                break;
            }
            // end of all groups
            if(l_dap_db_log_list->group_cur >= l_dap_db_log_list->group_number) {
                pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
                break;
            }
            l_dap_db_log_list->item_start = 0;
            l_dap_db_log_list->item_last = l_dap_db_log_list->group_last_id[l_dap_db_log_list->group_cur];
            l_item_start = l_dap_db_log_list->item_start;
            l_item_last = l_dap_db_log_list->item_last;
            if(l_dap_db_log_list->group_cur == -1)
                l_group_cur_name = GROUP_LOCAL_HISTORY;
            else
                l_group_cur_name = l_dap_db_log_list->group_names[l_dap_db_log_list->group_cur];
            pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);

            //l_item_count = min(10, (int64_t)l_item_last - (int64_t)l_item_start + 1);
            //if(l_item_count<=0)
            //    continue;
            // read next 1...10 items
            //l_objs = dap_chain_global_db_cond_load(l_group_cur_name, l_item_start, &l_item_count);
            continue;
        }
        //if(!l_objs)
            //continue;
        dap_list_t *l_list = NULL;
        for(size_t i = 0; i < l_item_count; i++) {
            dap_store_obj_t *l_obj_cur = l_objs + i;
            dap_global_db_obj_t *l_item = DAP_NEW(dap_global_db_obj_t);
            l_item->id = l_obj_cur->id;
            l_item->key = dap_strdup(l_obj_cur->key);
            l_item->value = (uint8_t*) dap_strdup((char*) l_obj_cur->value);
            l_list = dap_list_append(l_list, l_item);
        }
        pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
        // add l_list to list_write
        l_dap_db_log_list->list_write = dap_list_concat(l_dap_db_log_list->list_write, l_list);
        // init read list if it ended already
        if(!l_dap_db_log_list->list_read)
            l_dap_db_log_list->list_read = l_list;
        // set new start pos = lastitem pos + 1
        if(l_item_count > 0)
            l_dap_db_log_list->item_start = l_objs[l_item_count - 1].id + 1;
        //else
        //    l_dap_db_log_list->item_start += l_data_size_out;
        pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
        l_items_number += l_item_count;
        //log_it(L_DEBUG, "loaded items n=%u/%u", l_data_size_out, l_items_number);
        dap_store_obj_free(l_objs, l_item_count);
    }

    pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
    l_dap_db_log_list->is_process = false;
    pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
    return NULL;
}

/**
 * instead dap_db_log_get_list()
 */
dap_db_log_list_t* dap_db_log_list_start(uint64_t first_id, dap_list_t *a_add_groups_mask)
{

    //log_it(L_DEBUG, "Start loading db list_write...");

    size_t l_add_groups_num = 0;// number of group
    dap_list_t *l_add_groups_mask = a_add_groups_mask;
    // calc l_add_groups_num
    while(l_add_groups_mask) {
        // не считать группы del
        dap_list_t *l_groups = dap_chain_global_db_driver_get_groups_by_mask(l_add_groups_mask->data);
        l_add_groups_num += dap_list_length(l_groups);
        dap_list_free_full(l_groups, (dap_callback_destroyed_t) free);
        l_add_groups_mask = dap_list_next(l_add_groups_mask);
    }
    if(l_add_groups_num == 0)
        return NULL;

    size_t l_data_size_out_main = dap_db_log_get_last_id() - first_id + 1;
            //dap_chain_global_db_driver_count(GROUP_LOCAL_HISTORY, first_id); - not working for sqlite
    size_t *l_data_size_out_add_items = DAP_NEW_Z_SIZE(size_t, sizeof(size_t) * l_add_groups_num);
    uint64_t *l_group_last_id = DAP_NEW_Z_SIZE(uint64_t, sizeof(uint64_t) * l_add_groups_num);
    char **l_group_names = DAP_NEW_Z_SIZE(char*, sizeof(char*) * l_add_groups_num);
    size_t l_data_size_out_add_items_count = 0;
    l_add_groups_mask = a_add_groups_mask;
    while(l_add_groups_mask){
        dap_list_t *l_groups0 = dap_chain_global_db_driver_get_groups_by_mask(l_add_groups_mask->data);
        dap_list_t *l_groups = l_groups0;
        size_t l_group_cur = 0;
        while(l_groups){
            const char *l_group_name = (const char *) l_groups->data;
            l_group_names[l_group_cur] = dap_strdup(dap_chain_global_db_get_history_group_by_group_name(l_group_name));
            dap_store_obj_t *l_obj = dap_chain_global_db_driver_read_last(l_group_names[l_group_cur]);
            if(l_obj) {
                l_group_last_id[l_group_cur] = l_obj->id;
                dap_store_obj_free(l_obj, 1);
            }
            l_data_size_out_add_items[l_group_cur] = dap_chain_global_db_driver_count(l_group_names[l_group_cur], 1);
            l_data_size_out_add_items_count += l_data_size_out_add_items[l_group_cur];
            l_group_cur++;
            l_groups = dap_list_next(l_groups);
        }
        dap_list_free_full(l_groups0, (dap_callback_destroyed_t) free);
        l_add_groups_mask = dap_list_next(l_add_groups_mask);
    }
    if(!(l_data_size_out_main + l_data_size_out_add_items_count)){
        DAP_DELETE(l_data_size_out_add_items);
        DAP_DELETE(l_group_last_id);
        DAP_DELETE(l_group_names);
        return NULL;
    }
    dap_db_log_list_t *l_dap_db_log_list = DAP_NEW_Z(dap_db_log_list_t);
    l_dap_db_log_list->item_start = first_id;
    l_dap_db_log_list->item_last = first_id + l_data_size_out_main;
    l_dap_db_log_list->items_number_main = l_data_size_out_main;
    l_dap_db_log_list->items_number_add = l_data_size_out_add_items_count;
    l_dap_db_log_list->items_number = l_data_size_out_main + l_data_size_out_add_items_count;
    l_dap_db_log_list->items_rest = l_dap_db_log_list->items_number;
    l_dap_db_log_list->group_number = (int64_t)l_add_groups_num;
    l_dap_db_log_list->group_number_items = l_data_size_out_add_items;
    l_dap_db_log_list->group_last_id = l_group_last_id;
    l_dap_db_log_list->group_names = l_group_names;
    l_dap_db_log_list->group_cur = -1;
    l_dap_db_log_list->add_groups = a_add_groups_mask;
    l_dap_db_log_list->is_process = true;
    pthread_mutex_init(&l_dap_db_log_list->list_mutex, NULL);
    pthread_create(&l_dap_db_log_list->thread, NULL, s_list_thread_proc, l_dap_db_log_list);
    return l_dap_db_log_list;
}

/**
 * Get number of items
 */
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return 0;
    size_t l_items_number;
    pthread_mutex_lock(&a_db_log_list->list_mutex);
    l_items_number = a_db_log_list->items_number;
    pthread_mutex_unlock(&a_db_log_list->list_mutex);
    return l_items_number;
}

size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return 0;
    size_t l_items_rest;
    pthread_mutex_lock(&a_db_log_list->list_mutex);
    l_items_rest = a_db_log_list->items_rest;
    pthread_mutex_unlock(&a_db_log_list->list_mutex);
    return l_items_rest;
}
/**
 * Get one item from log_list
 */
dap_global_db_obj_t* dap_db_log_list_get(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return NULL;
    dap_list_t *l_list;
    bool l_is_process;
    int l_count = 0;
    while(1) {
        pthread_mutex_lock(&a_db_log_list->list_mutex);
        l_is_process = a_db_log_list->is_process;
        // check next item
        l_list = a_db_log_list->list_read;
        if (l_list){
            a_db_log_list->list_read = dap_list_next(a_db_log_list->list_read);
            a_db_log_list->items_rest--;
        }
        pthread_mutex_unlock(&a_db_log_list->list_mutex);
        // wait reading next item, no more 1 sec (50 ms * 100 times)
        if(!l_list && l_is_process) {
            dap_usleep(DAP_USEC_PER_SEC / 200);
            l_count++;
            if(l_count > 100)
                break;
        }
        else
            break;
    }
    //log_it(L_DEBUG, "get item n=%d", a_db_log_list->items_number - a_db_log_list->items_rest);
    return (dap_global_db_obj_t*) l_list ? l_list->data : NULL;
    //return l_list;
}

/**
 * Get log diff as list_write
 */
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return;
    // stop thread if it has created
    if(a_db_log_list->thread) {
        pthread_mutex_lock(&a_db_log_list->list_mutex);
        a_db_log_list->is_process = false;
        pthread_mutex_unlock(&a_db_log_list->list_mutex);
        pthread_join(a_db_log_list->thread, NULL);
    }
    for(int64_t i = 0; i < a_db_log_list->group_number; i++)
        DAP_DELETE(a_db_log_list->group_names[i]);
    DAP_DELETE(a_db_log_list->group_names);
    DAP_DELETE(a_db_log_list->group_last_id);
    DAP_DELETE(a_db_log_list->group_number_items);
    dap_list_free(a_db_log_list->add_groups);
    dap_list_free_full(a_db_log_list->list_write, (dap_callback_destroyed_t) dap_chain_global_db_obj_delete);
    pthread_mutex_destroy(&a_db_log_list->list_mutex);
    DAP_DELETE(a_db_log_list);
}
