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

// The function does nothing
static inline void lock()
{
    //pthread_mutex_lock(&ldb_mutex_);
}

// The function does nothing
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

static int s_track_history = 0;

int     s_db_drvmode_async ,                                                /* Set a kind of processing requests to DB:
                                                                            <> 0 - Async mode should be used */
        s_dap_global_db_debug_more;                                         /* Enable extensible debug output */

/**
 * @brief Adds a group name for synchronization.
 * @param a_group_prefix a prefix of the group name
 * @param a_callback a callback function
 * @param a_arg a pointer to an argument
 * @return (none)
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
 * @brief Adds a group name for synchronization with especially node addresses.
 * @param a_group_mask a group mask string
 * @param a_callback a callabck function
 * @param a_arg a pointer to an argument
 * @return (none)
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

/**
 * @brief Gets a list of a group mask.
 * @param a_table a table
 * @return Returns a pointer to a list of a group mask.
 */
dap_list_t *dap_chain_db_get_sync_groups_internal(sync_group_item_t *a_table)
{
    dap_list_t *l_ret = NULL;
    sync_group_item_t *l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, a_table, l_item, l_item_tmp) {
        l_ret = dap_list_append(l_ret, l_item->group_mask);
    }
    return l_ret;
}

/**
 * @brief Gets a list of a group mask for s_sync_group_items.
 * @return Returns a pointer to a list of a group mask.
 */
dap_list_t *dap_chain_db_get_sync_groups()
{
    return dap_chain_db_get_sync_groups_internal(s_sync_group_items);
}

/**
 * @brief Gets a list of a group mask for s_sync_group_items.
 * @param a_table a table
 * @return Returns a pointer to a list of a group mask.
 */
dap_list_t *dap_chain_db_get_sync_extra_groups()
{
    return dap_chain_db_get_sync_groups_internal(s_sync_group_extra_items);
}

/**
 * @brief Deallocates memory of a key and a value members of an obj structure.
 * @param obj a pointer to the structure
 * @return (none)
 */
void dap_chain_global_db_obj_clean(dap_global_db_obj_t *a_obj)
{
    if(!a_obj)
        return;

    DAP_DELETE(a_obj->key);
    DAP_DELETE(a_obj->value);

    a_obj->key = NULL;
    a_obj->value = NULL;
}

/**
 * @brief Deallocates memory of an obj structure.
 * @param obj a pointer to the object
 * @return (none)
 */
void dap_chain_global_db_obj_delete(dap_global_db_obj_t *a_obj)
{
    dap_chain_global_db_obj_clean(a_obj);
    DAP_DELETE(a_obj);
}

/**
 * @brief Deallocates memory of an objs array.
 * @param objs a pointer to the first object of the array
 * @param a_count a number of objects in the array
 * @return (none)
 */
void dap_chain_global_db_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count)
{
dap_global_db_obj_t *l_objs;
size_t i;

    if ( !a_objs || !a_count )                              /* Sanity checks */
        return;

    for(l_objs = a_objs, i = a_count; i--; l_objs++)        /* Run over array's elements */
        dap_chain_global_db_obj_clean(a_objs);

    DAP_DELETE(a_objs);                                     /* Finaly kill the the array */
}

/**
 * @brief Initializes a database by g_config structure.
 * @note You should call this function before calling any other functions in this library.
 * @param g_config a pointer to the configuration structure
 * @return Returns 0 if successful; otherwise, <0.
 */
int dap_chain_global_db_init(dap_config_t * g_config)
{
    const char *l_storage_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
    const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "sqlite");
    //const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "cdb");

    s_track_history = dap_config_get_item_bool_default(g_config, "resources", "dap_global_db_track_history", s_track_history);

    s_db_drvmode_async = dap_config_get_item_bool(g_config, "resources", "dap_global_db_drvmode_async");
    log_it(L_NOTICE,"DB Driver Async mode: %s", s_db_drvmode_async ? "ON": "OFF");

    s_dap_global_db_debug_more = dap_config_get_item_bool(g_config, "resources", "debug_more");

    //debug_if(s_dap_global_db_debug_more, L_DEBUG, "Just a test for %d", 135);

    lock();
    int res = dap_db_driver_init(l_driver_name, l_storage_path, s_db_drvmode_async);
    unlock();

    if( res != 0 )
        log_it(L_CRITICAL, "Hadn't initialized db driver \"%s\" on path \"%s\"", l_driver_name, l_storage_path);
    else
        log_it(L_NOTICE, "GlobalDB initialized");

    return res;
}

/**
 * @brief Deinitialize a database.
 * @note You should call this function at the end.
 * @return (none)
 */
void dap_chain_global_db_deinit(void)
{
sync_group_item_t *l_item = NULL, *l_item_tmp = NULL,
        *l_add_item = NULL, *l_add_item_tmp = NULL;

    lock();
    dap_db_driver_deinit();
    unlock();

    HASH_ITER(hh, s_sync_group_items, l_item, l_item_tmp)
    {
        DAP_DELETE(l_item->group_name_for_history);
        DAP_DELETE(l_item);
    }

    HASH_ITER(hh, s_sync_group_extra_items, l_add_item, l_add_item_tmp)
    {
        DAP_DELETE(l_add_item->group_mask);
        DAP_DELETE(l_add_item->group_name_for_history);
        DAP_DELETE(l_add_item);
    }

    s_sync_group_items = NULL;
}

/**
 * @brief Flushes a database cahce to disk.
 * @return 0
 */
int dap_chain_global_db_flush(void)
{
    lock();
    int res = dap_db_driver_flush();
    unlock();

    return res;
}

/**
 * @brief Gets an object from a database by a_key and a_group arguments.
 * @param a_key an object key string
 * @param a_group a group name string
 * @return If successful, returns a pointer to the item, otherwise NULL.
 */
void* dap_chain_global_db_obj_get(const char *a_key, const char *a_group)
{
    size_t l_count = 1;
    // read one item
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_count);
    return l_store_data;
}

/**
 * @brief Gets an array consisting of a_data_len_out objects from a database by a_key and a_group arguments.
 * @param a_key an object key string
 * @param a_data_len_out[in] a number of objects to be gotten, if NULL - no limits
 * @param a_data_len_out[out] a number of objects that were gotten
 * @param a_group a group name string
 * @return If successful, returns a pointer to the first item in the array; otherwise NULL.
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
 * @brief Gets an object value from database by a_key and a_group.
 *
 * @param a_key an object key string
 * @param a_data_len_out a length of values that were gotten
 * @param a_group a group name string
 * @return If successful, returns a pointer to the object value.
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

/**
 * @brief Gets an object value from database by a_key for the "local.general" group.
 * @param a_key an object key string
 * @param a_data_len_out a length of value that was gotten
 * @return If successful, returns a pointer to the object value, otherwise NULL.
 */
uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_len_out)
{
    return dap_chain_global_db_gr_get(a_key, a_data_len_out, GROUP_LOCAL_GENERAL);
}

/**
 * @brief Adds info about the deleted entry to the database.
 * @param a_key an object key string
 * @param a_group a group name string
 * @param a_timestamp an object time stamp
 * @return True if successful, false otherwise.
 */
static int global_db_gr_del_add(const char *a_key, const char *a_group, time_t a_timestamp)
{
dap_store_obj_t store_data = {0};
char	l_group[DAP_DB_K_MAXGRPLEN];
int l_res = 0;

    store_data.key = a_key;
    // group = parent group + '.del'
    dap_snprintf(l_group, sizeof(l_group) - 1, "%s.del", a_group);
    store_data.group = l_group;
    store_data.timestamp = a_timestamp;

    lock();
    if (!dap_chain_global_db_driver_is(store_data.group, store_data.key))
        l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();

    return  (l_res >= 0);    /*  ? true : false; */
}

/**
 * @brief Deletes info about the deleted object from the database
 * @param a_key an object key string, looked like "0x8FAFBD00B..."
 * @param a_group a group name string, for example "kelvin-testnet.nodes"
 * @return If successful, returns true; otherwise, false.
 */
static int global_db_gr_del_del(const char *a_key, const char *a_group)
{
dap_store_obj_t store_data = {0};
char	l_group[DAP_DB_K_MAXGRPLEN];
int	l_res = 0;

    if(!a_key)
        return false;

    store_data.key = a_key;
    dap_snprintf(l_group, sizeof(l_group) - 1, "%s.del", a_group);
    store_data.group = l_group;

    lock();
    if ( dap_chain_global_db_driver_is(store_data.group, store_data.key) )
        l_res = dap_chain_global_db_driver_delete(&store_data, 1);
    unlock();

    return  (l_res >= 0);    /*  ? true : false; */
}

/**
 * @brief Gets time stamp of the deleted object by a_group and a_key arguments.
 * @param a_group a group name sring, for example "kelvin-testnet.nodes"
 * @param a_key an object key string, looked like "0x8FAFBD00B..."
 * @return If successful, a time stamp, otherwise 0.
 */
time_t global_db_gr_del_get_timestamp(const char *a_group, const char *a_key)
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
    DAP_DELETE((char *)store_data.group);
    return l_timestamp;
}

/**
 * @brief Deletes item from a database by a a_key for the "local.general" group.
 * @param a_key an object key string
 * @return True if successful, false otherwise.
 */
bool dap_chain_global_db_del(char *a_key)
{
    return dap_chain_global_db_gr_del(a_key, GROUP_LOCAL_GENERAL);
}

/**
 * @brief Gets a last item from a database by a_group.
 * @param a_group a group name string
 * @return If successful, a pointer to the object; otherwise NULL.
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
 * @brief Gets objects from a database by a_group_name and a_first_id.
 * @param a_group a group name string
 * @param a_first_id a first id
 * @param a_objs_count[in] a number of object to be read, if 0 - no limits
 * @param a_objs_count[out] a number of object were read
 * @return If successful, a pointer to objects; otherwise NULL.
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
 * @brief Gets all data from a database by a_group.
 * @param a_group a group name string
 * @param a_data_size[in] a poiter to return a number of data
 * @param a_data_size[out] a number of data
 * @return If successful, a pointer to data; otherwise NULL.
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

/**
 * @brief Gets all data from a database for the "local.general" group
 */
dap_global_db_obj_t* dap_chain_global_db_load(size_t *a_data_size_out)
{
    return dap_chain_global_db_gr_load(GROUP_LOCAL_GENERAL, a_data_size_out);
}

/**
 * @brief Finds item by a_items and a_group
 * @param a_items items
 * @param a_group a group name string
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

/**
 * @brief Adds data to the history log
 *
 * @param a_store_data a pointer to an object
 * @return (none)
 */
void dap_global_db_obj_track_history(dap_store_obj_t *a_store_data)
{
    dap_store_obj_t *l_obj = a_store_data;
    sync_group_item_t *l_sync_group_item = find_item_by_mask(s_sync_group_items, l_obj->group);

    if (l_sync_group_item) {
        if(l_sync_group_item->callback_notify) {
             l_sync_group_item->callback_notify(l_sync_group_item->callback_arg,
                        l_obj->type,
                        l_obj->group, l_obj->key,
                        l_obj->value, l_obj->value_len);
        }
        if (s_track_history) {
            lock();
            dap_db_history_add(l_obj->type, l_obj, 1, l_sync_group_item->group_name_for_history);
            unlock();
        }
    } else { // looking for extra group
        sync_group_item_t *l_sync_extra_group_item = find_item_by_mask(s_sync_group_extra_items, l_obj->group);
        if(l_sync_extra_group_item) {
            if(l_sync_extra_group_item->callback_notify) {
                l_sync_extra_group_item->callback_notify(l_sync_extra_group_item->callback_arg,
                        l_obj->type, l_obj->group, l_obj->key,
                        l_obj->value, l_obj->value_len);
            }
            if (s_track_history) {
                lock();
                dap_db_history_add(l_obj->type, l_obj, 1, l_sync_extra_group_item->group_name_for_history);
                unlock();
            }
        }
    }
}

/**
 * @brief Adds a value to a database.
 * @param a_key a object key string
 * @param a_value a value to be added
 * @param a_value_len length of value. If a_value_len=-1, the function calculates length.
 * @param a_group a group name string
 * @details Set one entry to base. IMPORTANT: a_key and a_value should be passed without free after (it will be released by gdb itself)
 * @return True if successful, false otherwise.
 */
bool dap_chain_global_db_gr_set(const char *a_key, const void *a_value, size_t a_value_len, const char *a_group)
{
dap_store_obj_t store_data = {0};

    store_data.key = a_key;
    store_data.value_len = (a_value_len == (size_t) -1) ? dap_strlen(a_value) : a_value_len;
    store_data.value = store_data.value_len ? a_value : NULL;
    store_data.group = a_group;
    store_data.timestamp = time(NULL);

    lock();
    int l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        // delete info about the deleted entry from the base if one present
        global_db_gr_del_del( a_key, a_group);

        store_data.value = a_value;
        store_data.key = a_key;

        dap_global_db_obj_track_history(&store_data);
    } else {
        log_it(L_ERROR, "Save error: %d", l_res);
    }

    return !l_res;
}

/**
 * @brief Adds a value to a database for the "local.general" group
 * @param a_value a value to be added
 * @param a_value_len length of value. If a_value_len=-1, the function counts length.
 * @return True if successful, false otherwise.
 */
bool dap_chain_global_db_set( char *a_key,  void *a_value, size_t a_value_len)
{
    return dap_chain_global_db_gr_set(a_key, a_value, a_value_len, GROUP_LOCAL_GENERAL);
}

/**
 * @brief Deletes object from a database by a a_key and a_group arguments.
 * @param a_key a object key string
 * @param a_group a group name string
 * @return True if object was deleted or false otherwise.
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group)
{
dap_store_obj_t store_data = {0};

    store_data.key = a_key;
    store_data.group = (char*)a_group;

    lock();
    int l_res = dap_chain_global_db_driver_delete(&store_data, 1);
    unlock();

    if (a_key) {
        if (l_res >= 0) {
            // add to Del group
            global_db_gr_del_add(a_key, store_data.group, time(NULL));
        }
        // do not add to history if l_res=1 (already deleted)
        if (!l_res) {
            store_data.key = (char *) a_key;
            dap_global_db_obj_track_history(&store_data);
        }
    }
    return !l_res;
}

/**
 * @brief Saves(deletes) objects to (from) a database.
 * @param a_store_data a pointer to objects
 * @param a_objs_count a number of objects
 * @return True if object was deleted or false otherwise.
 */
bool dap_chain_global_db_obj_save(dap_store_obj_t *a_store_data, size_t a_objs_count)
{
dap_store_obj_t *l_store_obj;

    /* Do we need something to do at all ? */
    if(!a_objs_count)
        return true;

    lock();
    int l_res = dap_chain_global_db_driver_apply(a_store_data, a_objs_count);
    unlock();

    l_store_obj = (dap_store_obj_t *)a_store_data;

    for(int  i = a_objs_count; i--; l_store_obj++) {
        if (l_store_obj->type == DAP_DB$K_OPTYPE_ADD && !l_res)
            // delete info about the deleted entry from the base if one present
            global_db_gr_del_del(l_store_obj->key, l_store_obj->group);
        else if (l_store_obj->type == DAP_DB$K_OPTYPE_ADD && l_res >= 0)
            // add to Del group
            global_db_gr_del_add(l_store_obj->key, l_store_obj->group, l_store_obj->timestamp);

        if (!l_res) {
            // Extract prefix if added successfuly, add history log and call notify callback if present
            dap_global_db_obj_track_history(l_store_obj);
        }
    }

    return !l_res;
}

/**
 * @brief Saves objects in a database by a_group.
 * @param a_objs a pointer to objects
 * @param a_objs_count a number of objects
 * @param a_group a group name string
 * @return If successful, true; otherwise false.
 */
bool dap_chain_global_db_gr_save(dap_global_db_obj_t* a_objs, size_t a_objs_count, const char *a_group)
{
dap_store_obj_t l_store_data[a_objs_count], *store_data_cur;
dap_global_db_obj_t *l_obj_cur;
time_t l_timestamp = time(NULL);

    store_data_cur = l_store_data;
    l_obj_cur = a_objs;

    for(int i = a_objs_count; i--; store_data_cur++, l_obj_cur++ ) {
        store_data_cur->type = DAP_DB$K_OPTYPE_ADD;
        store_data_cur->key = l_obj_cur->key;
        store_data_cur->group = (char*) a_group;
        store_data_cur->value = l_obj_cur->value;
        store_data_cur->value_len = l_obj_cur->value_len;
        store_data_cur->timestamp = l_timestamp;
    }

    return dap_chain_global_db_obj_save(l_store_data, a_objs_count);
}

/**
 * @brief Saves objectss in a database.
 * @param a_objs a pointer to objects
 * @param a_objs_count a number of objects
 * @return If successful, true; otherwise false.
 */
bool dap_chain_global_db_save(dap_global_db_obj_t* a_objs, size_t a_objs_count)
{
    return dap_chain_global_db_gr_save(a_objs, a_objs_count, GROUP_LOCAL_GENERAL);
}

/**
 * @brief Calcs a hash string for data
 * @param data a pointer to data
 * @param data_size a size of data
 * @return A hash string or NULL.
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size)
{
    return dap_chain_global_db_driver_hash(data, data_size);
}
