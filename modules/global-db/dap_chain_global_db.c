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
typedef struct history_group_item
{
    char prefix[32];
    uint8_t padding[7];
    bool auto_track; // Track history actions automaticly
    dap_global_db_obj_callback_notify_t callback_notify;
    void * callback_arg;
    char *group_name_for_history;
    UT_hash_handle hh;
} history_group_item_t;

// Callback table item
typedef struct history_extra_group_item
{
    char *group_name;
    char *group_name_for_history;
    dap_global_db_obj_callback_notify_t callback_notify;
    void * callback_arg;
    UT_hash_handle hh;
} history_extra_group_item_t;

// Tacked group callbacks
static history_group_item_t * s_history_group_items = NULL;
static history_extra_group_item_t * s_history_extra_group_items = NULL;
char * extract_group_prefix(const char * a_group);

/**
 * @brief extract_group_prefix
 * @param a_group
 * @return
 */
char * extract_group_prefix(const char* a_group)
{
    char * l_group_prefix = NULL, *l_delimeter;
    size_t l_group_prefix_size;

//    l_delimeter = index(a_group, '.');
    l_delimeter = strchr(a_group, '.');

    if(l_delimeter == NULL) {
        l_group_prefix = dap_strdup(a_group);
        l_group_prefix_size = dap_strlen(l_group_prefix) + 1;
    } else {
        l_group_prefix_size = (size_t) l_delimeter - (size_t) a_group;
        if(l_group_prefix_size > 1)
            l_group_prefix = strndup(a_group, l_group_prefix_size);
    }
    return l_group_prefix;
}


/*
 * Get history group by group name
 */
char* dap_chain_global_db_get_history_group_by_group_name(const char * a_group_name)
{
    if(!s_history_extra_group_items || !a_group_name)
        return NULL;
    history_extra_group_item_t * l_history_extra_group_item = NULL;
    HASH_FIND_STR(s_history_extra_group_items, a_group_name, l_history_extra_group_item);
    if(l_history_extra_group_item) {
        return dap_strdup(l_history_extra_group_item->group_name_for_history);
    }else
        return NULL;
}

/**
 * @brief dap_chain_global_db_add_history_group_prefix
 * @details Add group prefix that will be tracking all changes
 * @param a_group_prefix
 * @param a_group_name_for_history
 */
void dap_chain_global_db_add_history_group_prefix(const char * a_group_prefix, const char * a_group_name_for_history)
{
    history_group_item_t * l_item = DAP_NEW_Z(history_group_item_t);
    snprintf(l_item->prefix, sizeof(l_item->prefix), "%s", a_group_prefix);
    l_item->group_name_for_history = dap_strdup(a_group_name_for_history);//GROUP_LOCAL_HISTORY
    l_item->auto_track = true;
    HASH_ADD_STR(s_history_group_items, prefix, l_item);
}

/**
 * @brief dap_chain_global_db_add_history_callback_notify
 * @param a_group_prefix
 * @param a_callback
 */
void dap_chain_global_db_add_history_callback_notify(const char * a_group_prefix,
        dap_global_db_obj_callback_notify_t a_callback, void * a_arg)
{
    history_group_item_t * l_item = NULL;
    HASH_FIND_STR(s_history_group_items, a_group_prefix, l_item);
    if(l_item) {
        l_item->callback_notify = a_callback;
        l_item->callback_arg = a_arg;
    } else
        log_it(L_WARNING, "Can't setup notify callback for groups with prefix %s. Possible not in history track state",
                a_group_prefix);
}

/**
 * @brief dap_chain_global_db_add_history_extra_group
 * @details Add group prefix that will be tracking all changes
 * @param a_group_prefix
 */
const char* dap_chain_global_db_add_history_extra_group(const char * a_group_name, dap_chain_node_addr_t *a_nodes, uint16_t *a_nodes_count)
{
    history_extra_group_item_t* l_item = DAP_NEW_Z(history_extra_group_item_t);
    l_item->group_name = dap_strdup(a_group_name);
    l_item->group_name_for_history = dap_strdup_printf("local.history.%s", a_group_name);
    HASH_ADD_STR(s_history_extra_group_items, group_name, l_item);
    return (const char*)l_item->group_name_for_history;
}

/**
 * @brief dap_chain_global_db_add_history_extra_group_callback_notify
 * @param a_group_prefix
 * @param a_callback
 */
void dap_chain_global_db_add_history_extra_group_callback_notify(const char * a_group_prefix,
        dap_global_db_obj_callback_notify_t a_callback, void * a_arg)
{
    history_extra_group_item_t * l_item = NULL;
    HASH_FIND_STR(s_history_extra_group_items, a_group_prefix, l_item);
    if(l_item) {
        l_item->callback_notify = a_callback;
        l_item->callback_arg = a_arg;
    } else
        log_it(L_WARNING, "Can't setup notify callback for extra groups with prefix %s. Possible not in history track state",
                a_group_prefix);
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
    //int i = 0;
    //while(objs) {
    for(size_t i = 0; i < a_count; i++) {
        //if(!(objs[i]))
        //    break;
        dap_chain_global_db_obj_clean(objs + i);
        //i++;
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
    //const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "sqlite");
    const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver", "cdb");
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
    history_group_item_t * l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, s_history_group_items, l_item, l_item_tmp)
    {
        DAP_DELETE(l_item->group_name_for_history);
        DAP_DELETE(l_item);
    }
    history_extra_group_item_t * l_add_item = NULL, *l_add_item_tmp = NULL;
    HASH_ITER(hh, s_history_extra_group_items, l_add_item, l_add_item_tmp)
    {
        DAP_DELETE(l_add_item->group_name);
        DAP_DELETE(l_add_item->group_name_for_history);
        DAP_DELETE(l_add_item);
    }
    s_history_group_items = NULL;

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

    /*    size_t count = 0;
     if(!a_key)
     return NULL;
     size_t query_len = (size_t) snprintf(NULL, 0, "(&(cn=%s)(objectClass=%s))", a_key, a_group);
     char *query = DAP_NEW_Z_SIZE(char, query_len + 1); //char query[32 + strlen(a_key)];
     snprintf(query, query_len + 1, "(&(cn=%s)(objectClass=%s))", a_key, a_group); // objectClass != ou
     lock();
     dap_store_obj_t *store_data = dap_db_read_data(query, &count);
     unlock();
     assert(count <= 1);
     DAP_DELETE(query);
     return store_data;*/
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
    //uint8_t *l_ret_value = NULL;
    // read several items, 0 - no limits
    size_t l_data_len_out = 0;
    if(a_data_len_out)
        l_data_len_out = *a_data_len_out;
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_data_len_out);
    if(l_store_data) {
        //l_ret_value = (l_store_data->value) ? DAP_NEW_SIZE(uint8_t, l_store_data->value_len) : NULL; //ret_value = (store_data->value) ? strdup(store_data->value) : NULL;
        //memcpy(l_ret_value, l_store_data->value, l_store_data->value_len);
        if(a_data_len_out)
            *a_data_len_out = l_data_len_out;//l_store_data->value_len;
        //dap_store_obj_free(l_store_data, l_data_len_out);
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

    /*ldb
     *     uint8_t *l_ret_value = NULL;
     size_t l_count = 0;
     if(!a_key)
     return NULL;
     size_t l_query_len =(size_t) snprintf(NULL, 0, "(&(cn=%s)(objectClass=%s))", a_key, a_group);

     char *l_query = DAP_NEW_Z_SIZE(char, l_query_len + 1); //char query[32 + strlen(a_key)];
     snprintf(l_query, l_query_len + 1, "(&(cn=%s)(objectClass=%s))", a_key, a_group); // objectClass != ou
     lock();
     pdap_store_obj_t store_data = dap_db_read_data(l_query, &l_count);
     unlock();
     if(l_count == 1 && store_data && !strcmp(store_data->key, a_key)) {
     l_ret_value = (store_data->value) ? DAP_NEW_SIZE(uint8_t, store_data->value_len) : NULL; //ret_value = (store_data->value) ? strdup(store_data->value) : NULL;
     memcpy(l_ret_value, store_data->value, store_data->value_len);
     if(a_data_out)
     *a_data_out = store_data->value_len;
     }
     dap_store_obj_free(store_data, l_count);
     DAP_DELETE(l_query);
     return l_ret_value;*/
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
    dap_store_obj_t store_data;// = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.type = 'a';
    store_data.key = a_key;//dap_strdup(a_key);
    // no data
    store_data.value = NULL;
    store_data.value_len = 0;
    // group = parent group + '.del'
    store_data.group = dap_strdup_printf("%s.del", a_group);
    store_data.timestamp = a_timestamp;//time(NULL);
    lock();
    int l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();
    DAP_DELETE(store_data.group);
    if(l_res>=0)
        return true;
    return false;
}

/**
 * Delete info about the deleted entry from the base
 */
static bool global_db_gr_del_del(char *a_key,const char *a_group)
{
    if(!a_key)
        return NULL;
    dap_store_obj_t store_data;// = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
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
    if(dap_chain_global_db_driver_is(store_data.group, store_data.key)) {
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

/**
 *
 */

/**
 * @brief dap_chain_global_db_gr_set
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_group
 * @details Set one entry to base. IMPORTANT: a_key and a_value should be passed without free after (it will be released by gdb itself)
 * @return
 */
bool dap_chain_global_db_gr_set(char *a_key, void *a_value, size_t a_value_len,  const char *a_group)
{
    dap_store_obj_t store_data;// = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.type = 'a';
    store_data.key = a_key;//dap_strdup(a_key);
    store_data.value = a_value;//DAP_NEW_Z_SIZE(uint8_t, a_value_len);

    //memcpy(store_data.value, a_value, a_value_len);

    store_data.value_len = (a_value_len == (size_t) -1) ? dap_strlen((const char*) a_value) : a_value_len;
    store_data.group = (char*)a_group;//dap_strdup(a_group);
    store_data.timestamp = time(NULL);
    lock();
    int l_res = dap_chain_global_db_driver_add(&store_data, 1);
    unlock();

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        // Delete info about the deleted entry from the base if one present
        global_db_gr_del_del(a_key, a_group);

        char * l_group_prefix = extract_group_prefix(a_group);
        history_group_item_t * l_history_group_item = NULL;
        if(l_group_prefix)
            HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);

        if(l_history_group_item) {
            if(l_history_group_item->auto_track) {
                lock();
                dap_db_history_add('a', &store_data, 1, l_history_group_item->group_name_for_history);
                unlock();
            }
            if(l_history_group_item->callback_notify)
                l_history_group_item->callback_notify(l_history_group_item->callback_arg, 'a', l_group_prefix, a_group,
                        a_key, a_value, a_value_len);
        }
        // looking for extra group
        else {
            history_extra_group_item_t * l_history_extra_group_item = NULL;
            HASH_FIND_STR(s_history_extra_group_items, a_group, l_history_extra_group_item);

            if(l_history_extra_group_item) {
                lock();
                dap_db_history_add('a', &store_data, 1, l_history_extra_group_item->group_name_for_history);
                unlock();
                if(l_history_extra_group_item->callback_notify)
                    l_history_extra_group_item->callback_notify(l_history_extra_group_item->callback_arg, 'a',
                            l_group_prefix,
                            a_group,
                            a_key, a_value, a_value_len);
            }
        }
        if(l_group_prefix)
            DAP_DELETE(l_group_prefix);
    } else {
        log_it(L_ERROR, "Save error: %d", l_res);
    }
    //DAP_DELETE(store_data);

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
    dap_store_obj_t store_data;// = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    memset(&store_data, 0, sizeof(dap_store_obj_t));
    store_data.key = a_key;
    store_data.group = (char*)a_group;
    lock();
    int l_res = dap_chain_global_db_driver_delete(&store_data, 1);
    unlock();
    // do not add to history if l_res=1 (already deleted)
    if(!l_res) {
        // added to Del group
        global_db_gr_del_add(a_key, a_group, time(NULL));
        // Extract prefix
        char * l_group_prefix = extract_group_prefix(a_group);
        history_group_item_t * l_history_group_item = NULL;
        if(l_group_prefix)
            HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);
        if(l_history_group_item) {
            if(l_history_group_item->auto_track) {
                lock();
                dap_db_history_add('d', &store_data, 1, l_history_group_item->group_name_for_history);
                unlock();
            }
            if(l_history_group_item->callback_notify)
                l_history_group_item->callback_notify(l_history_group_item->callback_arg, 'd', l_group_prefix, a_group,
                        a_key, NULL, 0);
        }
        // looking for extra group
        else {
            history_extra_group_item_t * l_history_extra_group_item = NULL;
            HASH_FIND_STR(s_history_extra_group_items, a_group, l_history_extra_group_item);

            if(l_history_extra_group_item) {
                lock();
                dap_db_history_add('d', &store_data, 1, l_history_extra_group_item->group_name_for_history);
                unlock();
                if(l_history_extra_group_item->callback_notify)
                    l_history_extra_group_item->callback_notify(l_history_extra_group_item->callback_arg, 'd',
                            l_group_prefix, a_group, a_key, NULL, 0);
            }
        }
        if(l_group_prefix)
            DAP_DELETE(l_group_prefix);
    }
    //DAP_DELETE(store_data);
    if(l_res>=0){
        // added to Del group
        global_db_gr_del_add(a_key, a_group, time(NULL));
        /*/ read del info
        char *l_group = dap_strdup_printf("%s.del", a_group);
        size_t l_data_size_out = 0;
        dap_store_obj_t *l_objs = dap_chain_global_db_obj_gr_get(a_key, &l_data_size_out,l_group);
        // update timestamp
        if(l_objs){
            if(l_objs->timestamp<time(NULL))
        dap_store_obj_free(l_objs, l_data_size_out);
        }
        DAP_DELETE(l_group);*/
        return true;
    }
    return false;
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

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        for(size_t i = 0; i < a_objs_count; i++) {

            dap_store_obj_t *a_store_obj = a_store_data + i;
            if(a_store_obj->type == 'a')
                // delete info about the deleted entry from the base if one present
                global_db_gr_del_del(a_store_obj->key, a_store_obj->group);
            else if(a_store_obj->type == 'd')
                // add to Del group
                global_db_gr_del_add(a_store_obj->key, a_store_obj->group, a_store_obj->timestamp);


            history_group_item_t * l_history_group_item = NULL;
            dap_store_obj_t* l_obj = (dap_store_obj_t*)a_store_data + i;
            char * l_group_prefix = extract_group_prefix(l_obj->group);
            if(l_group_prefix)
                HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);

            if(l_history_group_item) {
                if(l_history_group_item->auto_track) {
                    lock();
                    dap_db_history_add((char)l_obj->type, l_obj, 1, l_history_group_item->group_name_for_history);
                    unlock();
                }
                if(l_history_group_item->callback_notify) {
                    if(l_obj) {
                        l_history_group_item->callback_notify(l_history_group_item->callback_arg,
                                (const char)l_obj->type,
                                l_group_prefix, l_obj->group, l_obj->key,
                                l_obj->value, l_obj->value_len);
                    } else {
                        break;
                    }
                }
            }
            // looking for extra group
            else {
                history_extra_group_item_t * l_history_extra_group_item = NULL;
                HASH_FIND_STR(s_history_extra_group_items, l_obj->group, l_history_extra_group_item);

                if(l_history_extra_group_item) {
                    lock();
                    dap_db_history_add((char)l_obj->type, l_obj, 1, l_history_extra_group_item->group_name_for_history);
                    unlock();
                    if(l_history_extra_group_item->callback_notify)
                        l_history_extra_group_item->callback_notify(l_history_extra_group_item->callback_arg,
                                (const char)l_obj->type,
                                l_group_prefix, l_obj->group, l_obj->key,
                                l_obj->value, l_obj->value_len);
                }
            }

            DAP_DELETE(l_group_prefix);
        }

    }
    if(l_res >= 0) {
        return true;
    }
    return false;
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
                history_group_item_t * l_history_group_item = NULL;
                dap_store_obj_t *l_obj = l_store_data + i;

                char * l_group_prefix = extract_group_prefix(l_obj->group);
                if(l_group_prefix)
                    HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);

                if(l_history_group_item) {
                    if(l_history_group_item->auto_track) {
                        lock();
                        dap_db_history_add('a', l_store_data, 1, l_history_group_item->group_name_for_history);
                        unlock();
                    }
                    if(l_history_group_item->callback_notify) {
                        if(l_obj) {
                            l_history_group_item->callback_notify(l_history_group_item->callback_arg, 'a',
                                    l_group_prefix, l_obj->group, l_obj->key,
                                    l_obj->value, l_obj->value_len);
                        } else {
                            break;
                        }
                    }
                }
                DAP_DELETE(l_group_prefix);
            }

        }
        DAP_DELETE(l_store_data); //dap_store_obj_free(store_data, a_objs_count);
        if(!l_res) {
            return true;
        }
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

/**
 * Parse data from dap_db_log_pack()
 *
 * return dap_store_obj_t*
 */
void* dap_db_log_unpack(const void *a_data, size_t a_data_size, size_t *a_store_obj_count)
{
    const dap_store_obj_pkt_t *l_pkt = (const dap_store_obj_pkt_t*) a_data;
    if (! l_pkt || ! a_data_size)
        return NULL;
    if( (l_pkt->data_size+ sizeof(dap_store_obj_pkt_t)) != ((size_t) a_data_size ))
        return NULL;

    size_t l_store_obj_count = 0;
    dap_store_obj_t *l_obj = dap_store_unpacket_multiple(l_pkt, &l_store_obj_count);
    if(a_store_obj_count)
        *a_store_obj_count = l_store_obj_count;

    return l_obj;
}

/**
 * Get timestamp from dap_db_log_pack()
 */
time_t dap_db_log_unpack_get_timestamp(uint8_t *a_data, size_t a_data_size)
{
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t*) a_data;
    if(!l_pkt || l_pkt->data_size != (a_data_size - sizeof(dap_store_obj_pkt_t)))
        return 0;
    return l_pkt->timestamp;
}

/**
 * Get log diff as string
 */
char* dap_db_log_get_diff(size_t *a_data_size_out)
{
    //DapList *l_group_list = dap_list_append(l_group_list,GROUP_HISTORY);
    size_t l_data_size_out = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    // make keys & val vector
    char **l_keys_vals0 = DAP_NEW_SIZE(char*, sizeof(char*) * (l_data_size_out * 2 + 2));
    char **l_keys_vals = l_keys_vals0 + 1;
    size_t i;
    // first element - number of records
    l_keys_vals0[0] = dap_strdup_printf("%d", l_data_size_out);
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs + i;
        l_keys_vals[i] = l_obj_cur->key;
        l_keys_vals[i + l_data_size_out] = (char*) l_obj_cur->value;
    }
    if(a_data_size_out)
        *a_data_size_out = l_data_size_out;
    // last element - NULL (marker)
    l_keys_vals[l_data_size_out * 2] = NULL;
    char *l_keys_vals_flat = dap_strjoinv(GLOBAL_DB_HIST_KEY_SEPARATOR, l_keys_vals0);
    DAP_DELETE(l_keys_vals0[0]);
    DAP_DELETE(l_keys_vals0);
    //dap_strfreev(l_keys_vals0);
    dap_chain_global_db_objs_delete(l_objs, l_data_size_out);
    return l_keys_vals_flat;
}
