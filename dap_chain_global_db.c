#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#include "uthash.h"

#include "dap_chain_common.h"
#include "dap_strfuncs.h"
//#include "dap_chain_global_db_pvt.h"
#include "dap_chain_global_db_driver.h"
#include "dap_chain_global_db_hist.h"
#include "dap_chain_global_db.h"

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
    UT_hash_handle hh;
} history_group_item_t;

// Tacked group callbacks
static history_group_item_t * s_history_group_items = NULL;

char * extract_group_prefix(const char * a_group);

/**
 * @brief extract_group_prefix
 * @param a_group
 * @return
 */
char * extract_group_prefix(const char * a_group)
{
    char * l_group_prefix = NULL, *l_delimeter;
    size_t l_group_prefix_size;
    l_delimeter = index(a_group, '.');
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

/**
 * @brief dap_chain_global_db_add_history_group_prefix
 * @details Add group prefix that will be tracking all changes
 * @param a_group_prefix
 */
void dap_chain_global_db_add_history_group_prefix(const char * a_group_prefix)
{
    history_group_item_t * l_item = DAP_NEW_Z(history_group_item_t);
    snprintf(l_item->prefix, sizeof(l_item->prefix), "%s", a_group_prefix);
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
 * Clean struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_clean(dap_global_db_obj_t *obj)
{
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
void dap_chain_global_db_objs_delete(dap_global_db_obj_t **objs)
{
    int i = 0;
    while(objs) {
        if(!(objs[i]))
            break;
        dap_chain_global_db_obj_clean(objs[i]);
        i++;
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
    const char *l_driver_name = dap_config_get_item_str_default(g_config, "resources", "dap_global_db_driver",
            "sqlite");
    lock();
    int res = dap_db_driver_init(l_driver_name, l_storage_path);
    //int res = dap_db_init(a_storage_path);
    unlock();
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
        DAP_DELETE(l_item);
    }
    s_history_group_items = NULL;

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
    if(a_data_len_out)
        *a_data_len_out = 0;
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, a_data_len_out);
    if(l_store_data) {
        l_ret_value = (l_store_data->value) ? DAP_NEW_SIZE(uint8_t, l_store_data->value_len) : NULL; //ret_value = (store_data->value) ? strdup(store_data->value) : NULL;
        memcpy(l_ret_value, l_store_data->value, l_store_data->value_len);
        if(a_data_len_out)
            *a_data_len_out = l_store_data->value_len;
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
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key, const void *a_value, size_t a_value_len, const char *a_group)
{
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->type = 'a';
    store_data->key = dap_strdup(a_key);
    store_data->value = DAP_NEW_Z_SIZE(uint8_t, a_value_len);

    memcpy(store_data->value, a_value, a_value_len);

    store_data->value_len = (a_value_len == (size_t) -1) ? dap_strlen((const char*) a_value) : a_value_len;
    store_data->group = dap_strdup(a_group);
    store_data->timestamp = time(NULL);
    lock();
    int l_res = dap_chain_global_db_driver_add(store_data, 1);
    unlock();

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        char * l_group_prefix = extract_group_prefix(a_group);
        history_group_item_t * l_history_group_item = NULL;
        if(l_group_prefix)
            HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);

        if(l_history_group_item) {
            if(l_history_group_item->auto_track) {
                lock();
                dap_db_history_add('a', store_data, 1);
                unlock();
            }
            if(l_history_group_item->callback_notify)
                l_history_group_item->callback_notify(l_history_group_item->callback_arg, 'a', l_group_prefix, a_group,
                        a_key, a_value, a_value_len);
        }
        if(l_group_prefix)
            DAP_DELETE(l_group_prefix);
    } else {
        log_it(L_ERROR, "Save error: %d", l_res);
    }
    DAP_DELETE(store_data);

    return !l_res;
}

bool dap_chain_global_db_set(const char *a_key, const void *a_value, size_t a_value_len)
{
    return dap_chain_global_db_gr_set(a_key, a_value, a_value_len, GROUP_LOCAL_GENERAL);
}
/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group)
{
    if(!a_key)
        return NULL;
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = dap_strdup(a_key);
    store_data->group = dap_strdup(a_group);
    lock();
    int l_res = dap_chain_global_db_driver_delete(store_data, 1);
    unlock();
    if(!l_res) {
        // Extract prefix
        char * l_group_prefix = extract_group_prefix(a_group);
        history_group_item_t * l_history_group_item = NULL;
        if(l_group_prefix)
            HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);
        if(l_history_group_item) {
            if(l_history_group_item->auto_track) {
                lock();
                dap_db_history_add('d', store_data, 1);
                unlock();
            }
            if(l_history_group_item->callback_notify)
                l_history_group_item->callback_notify(l_history_group_item->callback_arg, 'd', l_group_prefix, a_group,
                        a_key, NULL, 0);
        }
        if(l_group_prefix)
            DAP_DELETE(l_group_prefix);
    }
    DAP_DELETE(store_data);
    if(!l_res)
        return true;
    return false;
}
bool dap_chain_global_db_del(const char *a_key)
{
    return dap_chain_global_db_gr_del(a_key, GROUP_LOCAL_GENERAL);
}
/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_global_db_obj_t** dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out)
{
    size_t count = 0;
    // Read data
    lock();
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read(a_group, NULL, &count);
    unlock();
    if(!l_store_obj || !count)
        return NULL;
    dap_global_db_obj_t **l_data = DAP_NEW_Z_SIZE(dap_global_db_obj_t*,
            (count + 1) * sizeof(dap_global_db_obj_t*)); // last item in mass must be zero
    for(size_t i = 0; i < count; i++) {
        dap_store_obj_t *l_store_obj_cur = l_store_obj + i;
        assert(l_store_obj_cur);
        l_data[i] = DAP_NEW(dap_global_db_obj_t);
        l_data[i]->key = dap_strdup(l_store_obj_cur->key);
        l_data[i]->value_len = l_store_obj_cur->value_len;
        l_data[i]->value = DAP_NEW_Z_SIZE(uint8_t, l_store_obj_cur->value_len + 1);
        memcpy(l_data[i]->value, l_store_obj_cur->value, l_store_obj_cur->value_len);
    }
    dap_store_obj_free(l_store_obj, count);
    if(a_data_size_out)
        *a_data_size_out = count;
    return l_data;
    /*size_t l_query_len = (size_t) snprintf(NULL, 0, "(objectClass=%s)", a_group);
     char *l_query = DAP_NEW_Z_SIZE(char, l_query_len + 1);
     //const char *query = "(objectClass=addr_leased)";
     snprintf(l_query, l_query_len + 1, "(objectClass=%s)", a_group);
     size_t count = 0;
     // Read data
     lock();
     pdap_store_obj_t store_obj = dap_chain_global_db_driver_read(a_group, NULL, &count);
     unlock();
     DAP_DELETE(l_query);
     // Serialization data
     dap_store_obj_pkt_t *pkt = dap_store_packet_multiple(store_obj, 0, count);
     dap_store_obj_free(store_obj, count);
     if(pkt)
     {
     size_t count_new = 0;
     pdap_store_obj_t store_data = dap_store_unpacket_multiple(pkt, &count_new);
     assert(count_new == count);
     //char **data = DAP_NEW_SIZE(char*, (count_new + 1) * sizeof(char*));
     dap_global_db_obj_t **data = DAP_NEW_Z_SIZE(dap_global_db_obj_t*,
     (count_new + 1) * sizeof(dap_global_db_obj_t*)); // last item in mass must be zero
     for(size_t i = 0; i < count_new; i++) {
     pdap_store_obj_t store_data_cur = store_data + i;
     assert(store_data_cur);
     data[i] = DAP_NEW(dap_global_db_obj_t);
     data[i]->key = strdup(store_data_cur->key);
     data[i]->value_len = store_data_cur->value_len;
     data[i]->value = DAP_NEW_Z_SIZE(uint8_t, store_data_cur->value_len + 1);
     memcpy(data[i]->value, store_data_cur->value, store_data_cur->value_len);
     }
     DAP_DELETE(store_data);
     DAP_DELETE(pkt);
     if(a_data_size_out)
     *a_data_size_out = count_new;
     return data;
     }*/

}

dap_global_db_obj_t** dap_chain_global_db_load(size_t *a_data_size_out)
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
/*    dap_store_obj_t* l_store_data = (dap_store_obj_t*) a_store_data;
    if(l_store_data && a_objs_count > 0) {
        // real records
        size_t l_objs_count = a_objs_count;
        const char *l_group = l_store_data[0].group;

        // read data
        for(size_t i = 0; i < a_objs_count; i++) {
            dap_store_obj_t* l_obj = l_store_data + i;
            size_t l_count = 0;
            char *l_query = dap_strdup_printf("(&(cn=%s)(objectClass=%s))", l_obj->key, l_obj->group);
            lock();
            dap_store_obj_t *l_read_store_data = dap_chain_global_db_driver_read(l_query, NULL, &l_count);
            unlock();
            // whether to add a record
            if(l_obj->type == 'a' && l_read_store_data) {
                // don't save obj if (present timestamp) > (new timestamp)
                if(l_count == 1 && l_read_store_data->timestamp >= l_obj->timestamp) {
                    // mark to not save
                    l_obj->timestamp = (time_t) -1;
                    // reduce the number of real records
                    l_objs_count--;
                }
            }
            // whether to delete a record
            else if(l_obj->type == 'd' && !l_read_store_data) {

                // mark to not apply because record already deleted
                l_obj->timestamp = (time_t) -1;
                // reduce the number of real records
                l_objs_count--;
            }
            dap_store_obj_free(l_read_store_data, l_count);
            DAP_DELETE(l_query);
        }*/

    // save/delete data
    if(!a_objs_count)
        return true;

    lock();
    int l_res = dap_chain_global_db_driver_appy(a_store_data, a_objs_count);
    unlock();

    // Extract prefix if added successfuly, add history log and call notify callback if present
    if(!l_res) {
        for(size_t i = 0; i < a_objs_count; i++) {
            history_group_item_t * l_history_group_item = NULL;
            dap_store_obj_t* l_obj = a_store_data + i;
            char * l_group_prefix = extract_group_prefix(l_obj->group);
            if(l_group_prefix)
                HASH_FIND_STR(s_history_group_items, l_group_prefix, l_history_group_item);

            if(l_history_group_item) {
                if(l_history_group_item->auto_track) {
                    lock();
                    dap_db_history_add(l_obj->type, l_obj, 1);
                    unlock();
                }
                if(l_history_group_item->callback_notify) {
                    if(l_obj) {
                        l_history_group_item->callback_notify(l_history_group_item->callback_arg,
                                l_obj->type,
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
    if(!l_res)
        return true;
    return false;
}

bool dap_chain_global_db_gr_save(dap_global_db_obj_t* a_objs, size_t a_objs_count, const char *a_group)
{
    dap_store_obj_t *l_store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, a_objs_count * sizeof(struct dap_store_obj));
    time_t l_timestamp = time(NULL);
    char *l_group = dap_strdup(a_group);
    for(size_t q = 0; q < a_objs_count; ++q) {
        dap_store_obj_t *store_data_cur = l_store_data + q;
        dap_global_db_obj_t *a_obj_cur = a_objs + q;
        store_data_cur->key = a_obj_cur->key;
        store_data_cur->group = l_group;
        store_data_cur->value = a_obj_cur->value;
        store_data_cur->value_len = a_obj_cur->value_len;
        store_data_cur->timestamp = l_timestamp;
    }
    if(l_store_data) {
        lock();
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
                        dap_db_history_add('a', l_store_data, 1);
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
        if(!l_res){
            DAP_DELETE(l_group);
            return true;
        }
    }
    DAP_DELETE(l_group);
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
    if(!l_pkt || l_pkt->data_size != ((size_t) a_data_size - sizeof(dap_store_obj_pkt_t)))
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
    dap_global_db_obj_t **l_objs = dap_chain_global_db_gr_load(GROUP_LOCAL_HISTORY, &l_data_size_out);
    // make keys & val vector
    char **l_keys_vals0 = DAP_NEW_SIZE(char*, sizeof(char*) * (l_data_size_out * 2 + 2));
    char **l_keys_vals = l_keys_vals0 + 1;
    size_t i;
    // first element - number of records
    l_keys_vals0[0] = dap_strdup_printf("%d", l_data_size_out);
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs[i];
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
    dap_chain_global_db_objs_delete(l_objs);
    return l_keys_vals_flat;
}

/*char* dap_chain_global_db_hash_fast(const uint8_t *data, size_t data_size)
 {
 dap_chain_hash_fast_t a_hash;
 dap_hash((char*) data, data_size, a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_KECCAK);
 size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2;  heading 0x
 char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
 size_t hash_len = dap_chain_hash_to_str(&a_hash, a_str, a_str_max);
 if(!hash_len) {
 DAP_DELETE(a_str);
 return NULL ;
 }
 return a_str;
 }*/

