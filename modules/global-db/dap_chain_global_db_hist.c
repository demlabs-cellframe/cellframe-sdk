#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_string.h>
#include <dap_hash.h>
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_global_db_remote.h"
#include "dap_chain_global_db_hist.h"
#include "uthash.h"

//#define GDB_SYNC_ALWAYS_FROM_ZERO

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
        for(i = 0; i < a_dap_store_count; i++) {
            DAP_DELETE(l_keys[i]);
            DAP_DEL_Z(a_store_obj[i].value);
        }
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
    if(!l_res)
        return true;
    return false;
}

/**
 * Get last id in log
 */
uint64_t dap_db_log_get_group_last_id(const char *a_group_name)
{
    uint64_t result = 0;
    dap_store_obj_t *l_last_obj = dap_chain_global_db_get_last(a_group_name);
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
    return dap_db_log_get_group_last_id(GROUP_LOCAL_HISTORY);
}

/**
 * Thread for reading log list
 * instead dap_db_log_get_list()
 */
static void *s_list_thread_proc(void *arg)
{
    dap_db_log_list_t *l_dap_db_log_list = (dap_db_log_list_t *)arg;
    for (dap_list_t *l_groups = l_dap_db_log_list->groups; l_groups && l_dap_db_log_list->is_process; l_groups = dap_list_next(l_groups)) {
        dap_db_log_list_group_t *l_group_cur = (dap_db_log_list_group_t *)l_groups->data;
        char *l_del_group_name_replace = NULL;
        char l_obj_type;
        if (!dap_fnmatch("*.del", l_group_cur->name, 0)) {
            l_obj_type = 'd';
            size_t l_del_name_len = strlen(l_group_cur->name) - 4; //strlen(".del");
            l_del_group_name_replace = DAP_NEW_SIZE(char, l_del_name_len + 1);
            memcpy(l_del_group_name_replace, l_group_cur->name, l_del_name_len);
            l_del_group_name_replace[l_del_name_len] = '\0';
        } else {
            l_obj_type = 'a';
        }
        uint64_t l_item_start = l_group_cur->last_id_synced + 1;
        while (l_group_cur->count && l_dap_db_log_list->is_process) { // Number of records to be synchronized
            size_t l_item_count = min(32, l_group_cur->count);
            dap_store_obj_t *l_objs = dap_chain_global_db_cond_load(l_group_cur->name, l_item_start, &l_item_count);
            // go to next group
            if (!l_objs)
                break;
            // set new start pos = lastitem pos + 1
            l_item_start = l_objs[l_item_count - 1].id + 1;
            l_group_cur->count -= l_item_count;
            dap_list_t *l_list = NULL;
            for (size_t i = 0; i < l_item_count; i++) {
                dap_store_obj_t *l_obj_cur = l_objs + i;
                l_obj_cur->type = l_obj_type;
                if (l_obj_type == 'd') {
                    DAP_DELETE(l_obj_cur->group);
                    l_obj_cur->group = dap_strdup(l_del_group_name_replace);
                }
                dap_db_log_list_obj_t *l_list_obj = DAP_NEW_Z(dap_db_log_list_obj_t);
                uint64_t l_cur_id = l_obj_cur->id;
                l_obj_cur->id = 0;
                dap_store_obj_pkt_t *l_pkt = dap_store_packet_single(l_obj_cur);
                dap_hash_fast(l_pkt->data, l_pkt->data_size, &l_list_obj->hash);
                dap_store_packet_change_id(l_pkt, l_cur_id);
                l_list_obj->pkt = l_pkt;
                l_list = dap_list_append(l_list, l_list_obj);
                if (!l_dap_db_log_list->is_process)
                    break;
            }
            dap_store_obj_free(l_objs, l_item_count);
            pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
            // add l_list to list_write
            l_dap_db_log_list->list_write = dap_list_concat(l_dap_db_log_list->list_write, l_list);
            // init read list if it ended already
            if(!l_dap_db_log_list->list_read)
                l_dap_db_log_list->list_read = l_list;
            pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
        }

        if (l_del_group_name_replace)
            DAP_DELETE(l_del_group_name_replace);
    }

    pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
    l_dap_db_log_list->is_process = false;
    pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
    return NULL;
}

/**
 * instead dap_db_log_get_list()
 */
dap_db_log_list_t* dap_db_log_list_start(dap_chain_node_addr_t a_addr, int a_flags)
{
#ifdef GDB_SYNC_ALWAYS_FROM_ZERO
    a_flags |= F_DB_LOG_SYNC_FROM_ZERO;
#endif
    //log_it(L_DEBUG, "Start loading db list_write...");
    dap_db_log_list_t *l_dap_db_log_list = DAP_NEW_Z(dap_db_log_list_t);
    dap_list_t *l_groups_masks = dap_chain_db_get_sync_groups();
    if (a_flags & F_DB_LOG_ADD_EXTRA_GROUPS) {
        l_groups_masks = dap_list_concat(l_groups_masks, dap_chain_db_get_sync_extra_groups());
    }
    for (dap_list_t *l_cur_mask = l_groups_masks; l_cur_mask; l_cur_mask = dap_list_next(l_cur_mask)) {
        l_dap_db_log_list->groups = dap_list_concat(l_dap_db_log_list->groups,
                                                    dap_chain_global_db_driver_get_groups_by_mask(l_cur_mask->data));
    }
    dap_list_free(l_groups_masks);

    for (dap_list_t *l_groups = l_dap_db_log_list->groups; l_groups; l_groups = dap_list_next(l_groups)) {
        dap_db_log_list_group_t *l_replace = DAP_NEW_Z(dap_db_log_list_group_t);
        l_replace->name = (char *)l_groups->data;
        if (a_flags & F_DB_LOG_SYNC_FROM_ZERO)
            l_replace->last_id_synced = 0;
        else
            l_replace->last_id_synced = dap_db_get_last_id_remote(a_addr.uint64, l_replace->name);
        l_replace->count = dap_chain_global_db_driver_count(l_replace->name, l_replace->last_id_synced + 1);
        l_dap_db_log_list->items_number += l_replace->count;
        l_groups->data = (void *)l_replace;
    }
    l_dap_db_log_list->items_rest = l_dap_db_log_list->items_number;
    if (!l_dap_db_log_list->items_number) {
        DAP_DELETE(l_dap_db_log_list);
        return NULL;
    }
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
dap_db_log_list_obj_t* dap_db_log_list_get(dap_db_log_list_t *a_db_log_list)
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
    return l_list ? (dap_db_log_list_obj_t *)l_list->data : NULL;
    //return l_list;
}

void dap_db_log_list_delete_item(void *a_item)
{
    dap_db_log_list_obj_t *l_list_item = (dap_db_log_list_obj_t *)a_item;
    DAP_DELETE(l_list_item->pkt);
    DAP_DELETE(l_list_item);
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
    dap_list_free_full(a_db_log_list->groups, free);
    dap_list_free_full(a_db_log_list->list_write, (dap_callback_destroyed_t)dap_db_log_list_delete_item);
    pthread_mutex_destroy(&a_db_log_list->list_mutex);
    DAP_DELETE(a_db_log_list);
}
