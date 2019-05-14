#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_hist.h"

#define GROUP_HISTORY "history"

#define HIST_REC_SEPARATOR "\r;"
#define HIST_KEY_SEPARATOR "\a;"

static char* dap_db_history_pack_hist(dap_global_db_hist_t *a_rec)
{
    char *l_ret = dap_strdup_printf("%c%s%d%s%s%s%s", a_rec->type, HIST_REC_SEPARATOR, a_rec->keys_count,
    HIST_REC_SEPARATOR, a_rec->group, HIST_REC_SEPARATOR, a_rec->keys);
    return l_ret;
}

static int dap_db_history_unpack_hist(char *l_str_in, dap_global_db_hist_t *a_rec_out)
{
    char **l_strv = dap_strsplit(l_str_in, HIST_REC_SEPARATOR, -1);
    int l_count = dap_str_countv(l_strv);
    if(l_count != 4)
        return -1;
    a_rec_out->type = l_strv[0][0];
    a_rec_out->keys_count = strtod(l_strv[1], NULL);
    a_rec_out->group = dap_strdup(l_strv[2]);
    a_rec_out->keys = dap_strdup(l_strv[3]);
    dap_strfreev(l_strv);
    return 1;
}

static char* dap_db_history_timestamp()
{
    time_t l_cur_time = time(NULL);
    return dap_strdup_printf("%lld", (uint64_t) l_cur_time);
}

/**
 * Get data according the history log
 *
 * return dap_store_obj_pkt_t*
 */
uint8_t* dap_db_log_pack(dap_global_db_obj_t *a_obj, int *a_data_size_out)
{
    if(!a_obj)
        return NULL;
    dap_global_db_hist_t l_rec;
    if(dap_db_history_unpack_hist(a_obj->value, &l_rec) == -1)
        return NULL;
    time_t l_timestamp = strtoll(a_obj->key, NULL, 10);

    // parse global_db records in a history record
    char **l_keys = dap_strsplit(l_rec.keys, HIST_KEY_SEPARATOR, -1);
    int l_count = dap_str_countv(l_keys);
    // read records from global_db
    int i = 0;
    dap_store_obj_t *l_store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count * sizeof(dap_store_obj_t));
    while(l_keys[i]) {

        dap_store_obj_t *l_obj = (dap_store_obj_t*) dap_chain_global_db_obj_get(l_keys[i], l_rec.group);
        if (l_obj == NULL){
            dab_db_free_pdap_store_obj_t(l_store_obj, l_count);
            dap_strfreev(l_keys);
            return NULL;
        }
        memcpy(l_store_obj + i, l_obj, sizeof(dap_store_obj_t));
        DAP_DELETE(l_obj);
        i++;
    };
    // serialize data
    dap_store_obj_pkt_t *l_data_out = dap_store_packet_multiple(l_store_obj, l_timestamp, l_count);

    dab_db_free_pdap_store_obj_t(l_store_obj, l_count);
    dap_strfreev(l_keys);

    if(l_data_out && a_data_size_out) {
        *a_data_size_out = sizeof(dap_store_obj_pkt_t) + l_data_out->data_size;
    }
    return (uint8_t*) l_data_out;

}

/**
 * Parse data from dap_db_log_pack()
 *
 * return dap_store_obj_t*
 */
void* dap_db_log_unpack(uint8_t *a_data, int a_data_size, int *a_store_obj_count)
{
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t*) a_data;
    if(!l_pkt || l_pkt->data_size != (a_data_size - sizeof(dap_store_obj_pkt_t)))
        return NULL;
    int l_store_obj_count = 0;
    dap_store_obj_t *l_obj = dap_store_unpacket(l_pkt, &l_store_obj_count);
    if(a_store_obj_count)
        *a_store_obj_count = l_store_obj_count;
    return l_obj;
}

/**
 * Get timestamp from dap_db_log_pack()
 */
time_t dap_db_log_unpack_get_timestamp(uint8_t *a_data, int a_data_size)
{
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t*) a_data;
    if(!l_pkt || l_pkt->data_size != (a_data_size - sizeof(dap_store_obj_pkt_t)))
        return 0;
    return l_pkt->timestamp;
}

/**
 * Add data to the history log
 */
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, int a_dap_store_count)
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
        char **l_keys = DAP_NEW_Z_SIZE(char*, sizeof(char*) * (a_dap_store_count + 1));
        int i;
        for(i = 0; i < a_dap_store_count; i++) {
            // if it is marked, the data has not been saved
            if(a_store_obj[i].timestamp == (time_t) -1)
                continue;
            l_keys[i] = a_store_obj[i].key;
        }
        l_keys[i] = NULL;
        l_rec.keys = dap_strjoinv(HIST_KEY_SEPARATOR, l_keys);
        DAP_DELETE(l_keys);
    }

    char *l_str = dap_db_history_pack_hist(&l_rec);
    size_t l_str_len = strlen(l_str);
    dap_store_obj_t l_store_data;
    // key - timestamp
    // value - keys of added/deleted data
    l_store_data.key = dap_db_history_timestamp();
    l_store_data.value = (char*) l_str;
    l_store_data.value_len = l_str_len;
    l_store_data.group = GROUP_HISTORY;
    l_store_data.timestamp = time(NULL);
    int l_res = dap_db_add(&l_store_data, 1);
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
    return true;
}

/**
 * Get last timestamp in log
 */
time_t dap_db_log_get_last_timestamp(void)
{
    char *last_key = NULL;
    size_t l_data_size_out = 0;
    dap_global_db_obj_t **l_objs = dap_chain_global_db_gr_load(GROUP_HISTORY, &l_data_size_out);
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
    time_t l_ret_time = strtoll(last_key, NULL, 10);
    dap_chain_global_db_objs_delete(l_objs);
    return l_ret_time;
}

static int compare_items(const void * l_a, const void * l_b)
{
    dap_global_db_obj_t *l_item_a = (dap_global_db_obj_t*) l_a;
    dap_global_db_obj_t *l_item_b = (dap_global_db_obj_t*) l_b;
    int l_ret = strcmp(l_item_a->key, l_item_b->key);
    return l_ret;
}

/**
 * Get log diff as list
 */
dap_list_t* dap_db_log_get_list(time_t first_timestamp)
{
    dap_list_t *l_list = NULL;
    char *l_first_key = dap_strdup_printf("%lld", (int64_t) first_timestamp);
    size_t l_data_size_out = 0;
    dap_global_db_obj_t **l_objs = dap_chain_global_db_gr_load(GROUP_HISTORY, &l_data_size_out);
    for(size_t i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs[i];
        if(strcmp(l_first_key, l_obj_cur->key) < 0) {
            dap_global_db_obj_t *l_item = DAP_NEW(dap_global_db_obj_t);
            l_item->key = dap_strdup(l_obj_cur->key);
            l_item->value = dap_strdup(l_obj_cur->value);
            l_list = dap_list_append(l_list, l_item);
        }
    }
    // sort list by key (time str)
    dap_list_sort(l_list, (dap_callback_compare_t) compare_items);

    /*/ dbg - sort result
     l_data_size_out = dap_list_length(l_list);
     for(size_t i = 0; i < l_data_size_out; i++) {
     dap_list_t *l_list_tmp = dap_list_nth(l_list, i);
     dap_global_db_obj_t *l_item = l_list_tmp->data;
     printf("2 %d %s\n", i, l_item->key);
     }*/

    DAP_DELETE(l_first_key);
    dap_chain_global_db_objs_delete(l_objs);
    return l_list;
}

/**
 * Free list getting from dap_db_log_get_list()
 */
void dap_db_log_del_list(dap_list_t *a_list)
{
    dap_list_free_full(a_list, (dap_callback_destroyed_t) dap_chain_global_db_obj_delete);
}

/**
 * Get log diff as string
 */
char* dap_db_log_get_diff(size_t *a_data_size_out)
{
    //DapList *l_group_list = dap_list_append(l_group_list,GROUP_HISTORY);
    size_t l_data_size_out = 0;
    dap_global_db_obj_t **l_objs = dap_chain_global_db_gr_load(GROUP_HISTORY, &l_data_size_out);
    // make keys & val vector
    char **l_keys_vals0 = DAP_NEW_SIZE(char*, sizeof(char*) * (l_data_size_out * 2 + 2));
    char **l_keys_vals = l_keys_vals0 + 1;
    int i;
    // first element - number of records
    l_keys_vals0[0] = dap_strdup_printf("%d", l_data_size_out);
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs[i];
        l_keys_vals[i] = l_obj_cur->key;
        l_keys_vals[i + l_data_size_out] = l_obj_cur->value;
    }
    // last element - NULL (marker)
    l_keys_vals[l_data_size_out * 2] = NULL;
    char *l_keys_vals_flat = dap_strjoinv(HIST_KEY_SEPARATOR, l_keys_vals0);
    DAP_DELETE(l_keys_vals0[0]);
    DAP_DELETE(l_keys_vals0);
    //dap_strfreev(l_keys_vals0);
    dap_chain_global_db_objs_delete(l_objs);
    return l_keys_vals_flat;
}

