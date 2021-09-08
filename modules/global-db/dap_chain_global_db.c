/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
* Copyright  (c) 2019-2020
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

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
//#include <string.h>

#include "uthash.h"
#include "dap_strfuncs.h"
#include "dap_chain_common.h"
#include "dap_chain_global_db_hist.h"
#include "dap_chain_global_db.h"

#ifdef WIN32
#include "registry.h"
#include <string.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 120
#endif

#define LOG_TAG "dap_global_db"


// for access from several streams
//static pthread_mutex_t ldb_mutex_ = PTHREAD_MUTEX_INITIALIZER;

static inline void lock()
{
    //pthread_mutex_lock(&ldb_mutex_);
}

static inline void unlock()
{
    //pthread_mutex_unlock(&ldb_mutex_);
}

// Callback table item
typedef struct sync_group_item
{
    char *group_mask;
    char *group_name_for_history;
    dap_global_db_obj_callback_notify_t callback_notify;
    void * callback_arg;
    UT_hash_handle hh;
} sync_group_item_t;

// Tacked group callbacks
static sync_group_item_t *s_sync_group_items = NULL;
static sync_group_item_t *s_sync_group_extra_items = NULL;
static bool s_track_history = false;

/**
 * @brief dap_chain_global_db_add_sync_group
 * @details Add group name for synchronization
 * @param a_group_prefix
 */
void dap_chain_global_db_add_sync_group(const char *a_group_prefix, dap_global_db_obj_callback_notify_t a_callback, void *a_arg)
{
    sync_group_item_t * l_item = DAP_NEW_Z(sync_group_item_t);
    l_item->group_mask = dap_strdup_printf("%s.*", a_group_prefix);
    l_item->group_name_for_history = dap_strdup(GROUP_LOCAL_HISTORY);
    l_item->callback_notify = a_callback;
    l_item->callback_arg = a_arg;
    HASH_ADD_STR(s_sync_group_items, group_mask, l_item);
}

/**
 * @brief dap_chain_global_db_add_sync_extra_group
 * @details Add group name for synchronization with especially node addresses
 * @param a_group_prefix
 */
void dap_chain_global_db_add_sync_extra_group(const char *a_group_mask, dap_global_db_obj_callback_notify_t a_callback, void *a_arg)
{
    sync_group_item_t* l_item = DAP_NEW_Z(sync_group_item_t);
    l_item->group_mask = dap_strdup(a_group_mask);
    l_item->group_name_for_history = dap_strdup(GROUP_LOCAL_HISTORY".extra");
    l_item->callback_notify = a_callback;
    l_item->callback_arg = a_arg;
    HASH_ADD_STR(s_sync_group_extra_items, group_mask, l_item);
}

dap_list_t *dap_chain_db_get_sync_groups_internal(sync_group_item_t *a_table)
{
    dap_list_t *l_ret = NULL;
    sync_group_item_t *l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, a_table, l_item, l_item_tmp) {
        l_ret = dap_list_append(l_ret, l_item->group_mask);
    }
    return l_ret;
}

dap_list_t *dap_chain_db_get_sync_groups()
{
    return dap_chain_db_get_sync_groups_internal(s_sync_group_items);
}

dap_list_t *dap_chain_db_get_sync_extra_groups()
{
    return dap_chain_db_get_sync_groups_internal(s_sync_group_extra_items);
}

/**
 * Clean struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_clean(dap_global_db_obj_t *obj)
{
    if(!obj)
        return;
    DAP_DELETE(obj->key);
    DAP_DELETE(obj->value);
    obj->key = NULL;
    obj->value = NULL;
}

/**
 * Delete struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_delete(dap_global_db_obj_t *obj)
{
    dap_chain_global_db_obj_clean(obj);
    DAP_DELETE(obj);
}

/**
 * Delete mass of struct dap_global_db_obj_t
 */
void dap_chain_global_db_objs_delete(dap_global_db_obj_t *objs, size_t a_count)
{
    for(size_t i = 0; i < a_count; i++) {
        dap_chain_global_db_obj_clean(objs + i);
    }
    DAP_DELETE(objs);
}

/**
 * @brief dap_chain_global_db_init
 * @param g_config
 * @return
 */
int dap_chain_global_db_init(dap_config_t * g_config)
{
    const char *l_storage_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
    const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "sqlite");
    //const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "cdb");
    s_track_history = dap_config_get_item_bool_default(g_config, "resources", "dap_global_db_track_history", s_track_history);
    lock();
    int res = dap_db_driver_init(l_driver_name, l_storage_path);
    unlock();
    if( res != 0 )
        log_it(L_CRITICAL, "Hadn't initialized db driver \"%s\" on path \"%s\"", l_driver_name, l_storage_path);
    else
        log_it(L_NOTICE,"GlobalDB initialized");
    return res;
}

/**
 * @brief dap_chain_global_db_deinit
 */
void dap_chain_global_db_deinit(void)
{
    lock();
    dap_db_driver_deinit();
    //dap_db_deinit();
    unlock();
    sync_group_item_t * l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, s_sync_group_items, l_item, l_item_tmp)
    {
        DAP_DELETE(l_item->group_name_for_history);
        DAP_DELETE(l_item);
    }
    sync_group_item_t * l_add_item = NULL, *l_add_item_tmp = NULL;
    HASH_ITER(hh, s_sync_group_extra_items, l_add_item, l_add_item_tmp)
    {
        DAP_DELETE(l_add_item->group_mask);
        DAP_DELETE(l_add_item->group_name_for_history);
        DAP_DELETE(l_add_item);
    }
    s_sync_group_items = NULL;

}

/**
 * @brief dap_chain_global_db_flush
 * @return
 */
int dap_chain_global_db_flush(void){
    lock();
    int res = dap_db_driver_flush();
    unlock();
    return res;
}

/**
 * Get entry from base
 *
 * return dap_store_obj_t*
 */
void* dap_chain_global_db_obj_get(const char *a_key, const char *a_group)
{
    size_t l_count = 1;
    // read one item
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_count);
    return l_store_data;
}

/**
 * @brief dap_chain_global_db_obj_gr_get
 * @param a_key
 * @param a_data_out
 * @param a_group
 * @return
 */
dap_store_obj_t* dap_chain_global_db_obj_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group)
{
    // read several items, 0 - no limits
    size_t l_data_len_out = 0;
    if(a_data_len_out)
        l_data_len_out = *a_data_len_out;
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_data_len_out);
    if(l_store_data) {
        if(a_data_len_out)
            *a_data_len_out = l_data_len_out;
    }
    return l_store_data;
}

/**
 * @brief dap_chain_global_db_gr_get
 * @param a_key
 * @param a_data_out
 * @param a_group
 * @return
 */
uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group)
{
    uint8_t *l_ret_value = NULL;
    // read several items, 0 - no limits
    size_t l_data_len_out = 0;
    if(a_data_len_out)
        l_data_len_out = *a_data_len_out;
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_data_len_out);
    if(l_store_data) {
        l_ret_value = (l_store_data->value) ? DAP_NEW_SIZE(uint8_t, l_store_data->value_len) : NULL; //ret_value = (store_data->value) ? strdup(store_data->value) : NULL;
        if(l_ret_value && l_store_data->value&& l_store_data->value_len)
            memcpy(l_ret_value, l_store_data->value, l_store_data->value_len);
        if(a_data_len_out)
            *a_data_len_out = l_store_data->value_len;
        dap_store_obj_free(l_store_data, l_data_len_out);
    }
    return l_ret_value;
}

uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_out)
{
    return dap_chain_global_db_gr_get(a_key, a_data_out, GROUP_LOCAL_GENERAL);
}


/**
 * Add info about the deleted entry to the base
 */
static bool global_db_gr_del_add(char *a_key,const char *a_group, time_t a_timestamp)
{
    dap_store_obj_t store_data;
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.type = 'a';
    store_data.key = a_key;
    // no data
    store_data.value = NULL;
    store_data.value_len = 0;
    // group = parent group + '.del'
    store_data.group = dap_strdup_printf("%s.del", a_group);
    store_data.timestamp = a_timestamp;
    lock();
    int l_res = 0;
    if (!dap_chain_global_db_driver_is(store_data.group, store_data.key))
        l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();
    DAP_DELETE(store_data.group);
    if(l_res>=0)
        return true;
    return false;
}

/**
 * Delete info about the deleted entry from the base
 */
static bool global_db_gr_del_del(char *a_key, const char *a_group)
{
    if(!a_key)
        return NULL;
    dap_store_obj_t store_data;
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.key = a_key;
   // store_data->c_key = a_key;
    store_data.group = dap_strdup_printf("%s.del", a_group);
    //store_data->c_group = a_group;
    lock();
    int l_res = 0;
    if(dap_chain_global_db_driver_is(store_data.group, store_data.key))
        l_res = dap_chain_global_db_driver_delete(&store_data, 1);
    unlock();
    DAP_DELETE(store_data.group);
    if(l_res>=0)
        return true;
    return false;
}

/**
 * Get timestamp of the deleted entry
 */
time_t global_db_gr_del_get_timestamp(const char *a_group, char *a_key)
{
    time_t l_timestamp = 0;
    if(!a_key)
        return l_timestamp;
    dap_store_obj_t store_data;
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.key = a_key;
    // store_data->c_key = a_key;
    store_data.group = dap_strdup_printf("%s.del", a_group);
    //store_data->c_group = a_group;
    lock();
    if (dap_chain_global_db_driver_is(store_data.group, store_data.key)) {
        size_t l_count_out = 0;
        dap_store_obj_t *l_obj = dap_chain_global_db_driver_read(store_data.group, store_data.key, &l_count_out);
        assert(l_count_out <= 1);
        l_timestamp = l_obj->timestamp;
        dap_store_obj_free(l_obj, l_count_out);
    }
    unlock();
    DAP_DELETE(store_data.group);
    return l_timestamp;
}


bool dap_chain_global_db_del(char *a_key)
{
    return dap_chain_global_db_gr_del(a_key, GROUP_LOCAL_GENERAL);
}

/**
 * Read last item in global_db
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_store_obj_t* dap_chain_global_db_get_last(const char *a_group)
{
    // Read data
    lock();
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read_last(a_group);
    unlock();
    return l_store_obj;
}

/**
 * Read the entire database with condition into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_store_obj_t* dap_chain_global_db_cond_load(const char *a_group, uint64_t a_first_id, size_t *a_objs_count)
{
    // Read data
    lock();
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_cond_read(a_group, a_first_id, a_objs_count);
    unlock();
    return l_store_obj;
}

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_global_db_obj_t* dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out)
{
    size_t count = 0;
    // Read data
    lock();
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read(a_group, NULL, &count);
    unlock();
    if(!l_store_obj || !count){
        if(a_data_size_out)
            *a_data_size_out = 0;
        return NULL;
    }
    dap_global_db_obj_t *l_data = DAP_NEW_Z_SIZE(dap_global_db_obj_t, (count + 1) * sizeof(dap_global_db_obj_t)); // last item in mass must be zero
    for(size_t i = 0; i < count; i++) {
        l_data[i].key = dap_strdup(l_store_obj[i].key);
        l_data[i].value_len = l_store_obj[i].value_len;
        l_data[i].value = DAP_NEW_Z_SIZE(uint8_t, l_store_obj[i].value_len + 1);
        memcpy(l_data[i].value, l_store_obj[i].value, l_store_obj[i].value_len);
    }
    dap_store_obj_free(l_store_obj, count);
    if(a_data_size_out)
        *a_data_size_out = count;
    return l_data;
}

dap_global_db_obj_t* dap_chain_global_db_load(size_t *a_data_size_out)
{
    return dap_chain_global_db_gr_load(GROUP_LOCAL_GENERAL, a_data_size_out);
}

/**
 * @brief extract_group_mask
 * @param a_group
 * @return
 */
static sync_group_item_t *find_item_by_mask(sync_group_item_t *a_items, const char *a_group)
{
    sync_group_item_t * l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, a_items, l_item, l_item_tmp) {
        if (!dap_fnmatch(l_item->group_mask, a_group, 0))
            return l_item;
    }
    return NULL;
}


void dap_global_db_obj_track_history(void* a_store_data)
{
    if (!s_track_history)
        return;
    dap_store_obj_t *l_obj = (dap_store_obj_t *)a_store_data;
    sync_group_item_t *l_sync_group_item = find_item_by_mask(s_sync_group_items, l_obj->group);
    if(l_sync_group_item) {
        lock();
        dap_db_history_add((char)l_obj->type, l_obj, 1, l_sync_group_item->group_name_for_history);
        unlock();
        if(l_sync_group_item->callback_notify) {
            if(l_obj) {
                l_sync_group_item->callback_notify(l_sync_group_item->callback_arg,
                        (const char)l_obj->type,
                        l_obj->group, l_obj->key,
                        l_obj->value, l_obj->value_len);
            }
        }
    } else { // looking for extra group
        sync_group_item_t *l_sync_extra_group_item = find_item_by_mask(s_sync_group_extra_items, l_obj->group);
        if(l_sync_extra_group_item) {
            lock();
            dap_db_history_add((char)l_obj->type, l_obj, 1, l_sync_extra_group_item->group_name_for_history);
            unlock();
            if(l_sync_extra_group_item->callback_notify)
                l_sync_extra_group_item->callback_notify(l_sync_extra_group_item->callback_arg,
                        (const char)l_obj->type, l_obj->group, l_obj->key,
                        l_obj->value, l_obj->value_len);
        }
    }
}


/**
 * @brief dap_chain_global_db_gr_set
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_group
 * @details Set one entry to base. IMPORTANT: a_key and a_value should be passed without free after (it will be released by gdb itself)
 * @return
 */
bool dap_chain_global_db_gr_set(char *a_key, void *a_value, size_t a_value_len, const char *a_group)
{
    dap_store_obj_t store_data;
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.key = a_key;
    store_data.value = a_value;
    store_data.value_len = (a_value_len == (size_t) -1) ? dap_strlen((const char*) a_value) : a_value_len;
    store_data.group = (char*)a_group;
    store_data.timestamp = time(NULL);
    lock();
    int l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        // delete info about the deleted entry from the base if one present
        global_db_gr_del_del(store_data.key, store_data.group);
        dap_global_db_obj_track_history(&store_data);
    } else {
        log_it(L_ERROR, "Save error: %d", l_res);
    }

    return !l_res;
}

bool dap_chain_global_db_set( char *a_key,  void *a_value, size_t a_value_len)
{
    return dap_chain_global_db_gr_set(a_key, a_value, a_value_len, GROUP_LOCAL_GENERAL);
}

/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(char *a_key,const char *a_group)
{
    if(!a_key)
        return NULL;
    dap_store_obj_t store_data;
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.key = a_key;
    store_data.group = (char*)a_group;
    lock();
    int l_res = dap_chain_global_db_driver_delete(&store_data, 1);
    unlock();
    if(l_res >= 0) {
        // add to Del group
        global_db_gr_del_add(store_data.key, store_data.group, store_data.timestamp);
    }
    // do not add to history if l_res=1 (already deleted)
    if (!l_res) {
        dap_global_db_obj_track_history(&store_data);
    }
    return !l_res;
}

/**
 * Write to the database from an array of data_size bytes
 *
 * @return
 */
bool dap_chain_global_db_obj_save(void* a_store_data, size_t a_objs_count)
{
    // save/delete data
    if(!a_objs_count)
        return true;

    lock();
    int l_res = dap_chain_global_db_driver_appy(a_store_data, a_objs_count);
    unlock();

    for(size_t i = 0; i < a_objs_count; i++) {
        dap_store_obj_t *a_store_obj = (dap_store_obj_t *)a_store_data + i;
        if (a_store_obj->type == 'a' && !l_res)
            // delete info about the deleted entry from the base if one present
            global_db_gr_del_del(a_store_obj->key, a_store_obj->group);
        else if (a_store_obj->type == 'd' && l_res >= 0)
            // add to Del group
            global_db_gr_del_add(a_store_obj->key, a_store_obj->group, a_store_obj->timestamp);
        if (!l_res)
        // Extract prefix if added successfuly, add history log and call notify callback if present
        dap_global_db_obj_track_history(a_store_obj);
    }
    return !l_res;
}

bool dap_chain_global_db_gr_save(dap_global_db_obj_t* a_objs, size_t a_objs_count, const char *a_group)
{
    dap_store_obj_t *l_store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, a_objs_count * sizeof(struct dap_store_obj));
    time_t l_timestamp = time(NULL);
    for(size_t q = 0; q < a_objs_count; ++q) {
        dap_store_obj_t *store_data_cur = l_store_data + q;
        dap_global_db_obj_t *a_obj_cur = a_objs + q;
        store_data_cur->key = a_obj_cur->key;
        store_data_cur->group = (char*)a_group;
        store_data_cur->value = a_obj_cur->value;
        store_data_cur->value_len = a_obj_cur->value_len;
        store_data_cur->timestamp = l_timestamp;
    }
    if(l_store_data) {
        lock();
        //log_it(L_DEBUG,"Added %u objects", a_objs_count);
        int l_res = dap_chain_global_db_driver_add(l_store_data, a_objs_count);
        unlock();
        if(!l_res) {    
            for(size_t i = 0; i < a_objs_count; i++) {
                dap_global_db_obj_track_history(l_store_data + i);
            }
        }
        DAP_DELETE(l_store_data);
        return !l_res;
    }
    return false;
}

bool dap_chain_global_db_save(dap_global_db_obj_t* a_objs, size_t a_objs_count)
{
    return dap_chain_global_db_gr_save(a_objs, a_objs_count, GROUP_LOCAL_GENERAL);
}

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size)
{
    return dap_chain_global_db_driver_hash(data, data_size);
}
