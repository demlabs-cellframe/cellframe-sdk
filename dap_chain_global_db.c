#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_global_db_pvt.h"
#include "dap_chain_global_db_hist.h"
#include "dap_chain_global_db.h"

// for access from several streams
static pthread_mutex_t ldb_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Check whether the data is local
 */
static bool is_local_group(const char *a_group)
{
    if( strncmp(a_group, "local.",6)==0 )
        return true;
    return false;
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

int dap_chain_global_db_init(dap_config_t * g_config)
{
    const char *a_storage_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
    if(a_storage_path)
    {
        pthread_mutex_lock(&ldb_mutex);
        int res = dap_db_init(a_storage_path);
        pthread_mutex_unlock(&ldb_mutex);
        return res;
    }
    return -1;
}

void dap_chain_global_db_deinit(void)
{
    pthread_mutex_lock(&ldb_mutex);
    dap_db_deinit();
    pthread_mutex_unlock(&ldb_mutex);
}

/**
 * Get entry from base
 *
 * return dap_store_obj_t*
 */
void* dap_chain_global_db_obj_get(const char *a_key, const char *a_group)
{
    int count = 0;
    if(!a_key)
        return NULL;
    size_t query_len = snprintf(NULL, 0, "(&(cn=%s)(objectClass=%s))", a_key, a_group);
    char *query = DAP_NEW_Z_SIZE(char, query_len + 1); //char query[32 + strlen(a_key)];
    snprintf(query, query_len + 1, "(&(cn=%s)(objectClass=%s))", a_key, a_group); // objectClass != ou
    pthread_mutex_lock(&ldb_mutex);
    dap_store_obj_t *store_data = dap_db_read_data(query, &count, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    assert(count <= 1);
    DAP_DELETE(query);
    return store_data;
}

uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_out, const char *a_group)
{
    uint8_t *l_ret_value = NULL;
    int l_count = 0;
    if(!a_key)
        return NULL;
    size_t l_query_len = snprintf(NULL, 0, "(&(cn=%s)(objectClass=%s))", a_key, a_group);
    char *l_query = DAP_NEW_Z_SIZE(char, l_query_len + 1); //char query[32 + strlen(a_key)];
    snprintf(l_query, l_query_len + 1, "(&(cn=%s)(objectClass=%s))", a_key, a_group); // objectClass != ou
    pthread_mutex_lock(&ldb_mutex);
    pdap_store_obj_t store_data = dap_db_read_data(l_query, &l_count, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    if(l_count == 1 && store_data && !strcmp(store_data->key, a_key)) {
        l_ret_value = (store_data->value) ? DAP_NEW_SIZE(uint8_t, store_data->value_len) : NULL; //ret_value = (store_data->value) ? strdup(store_data->value) : NULL;
        memcpy(l_ret_value, store_data->value, store_data->value_len);
        if(a_data_out)
            *a_data_out = store_data->value_len;
    }
    dab_db_free_pdap_store_obj_t(store_data, l_count);
    DAP_DELETE(l_query);
    return l_ret_value;
}

uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_out)
{
    return dap_chain_global_db_gr_get(a_key, a_data_out, GROUP_NAME_DEFAULT);
}

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key, const uint8_t *a_value, size_t a_value_len, const char *a_group)
{
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = (char*) a_key;
    store_data->value = (char*) a_value;
    store_data->value_len = (a_value_len == (size_t) -1) ? strlen(a_value) : a_value_len;
    store_data->group = (char*) a_group;
    store_data->timestamp = time(NULL);
    pthread_mutex_lock(&ldb_mutex);
    int res = dap_db_add(store_data, 1);
    if(!res && !is_local_group(a_group))
        dap_db_history_add('a', store_data, 1);
    pthread_mutex_unlock(&ldb_mutex);
    DAP_DELETE(store_data);
    if(!res)
        return true;
    return false;
}

bool dap_chain_global_db_set(const char *a_key, const uint8_t *a_value, size_t a_value_len)
{
    return dap_chain_global_db_gr_set(a_key, a_value, a_value_len, GROUP_NAME_DEFAULT);
}
/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group)
{
    char *str = NULL;
    if(!a_key)
        return NULL;
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = (char*) a_key;
    store_data->group = (char*) a_group;
    pthread_mutex_lock(&ldb_mutex);
    int res = dap_db_delete(store_data, 1);
    if(!res && !is_local_group(a_group))
        dap_db_history_add('d', store_data, 1);
    pthread_mutex_unlock(&ldb_mutex);
    DAP_DELETE(store_data);
    if(!res)
        return true;
    return false;
}
bool dap_chain_global_db_del(const char *a_key)
{
    return dap_chain_global_db_gr_del(a_key, GROUP_NAME_DEFAULT);
}
/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_global_db_obj_t** dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out)
{
    ssize_t query_len = snprintf(NULL, 0, "(objectClass=%s)", a_group);
    char *query = DAP_NEW_Z_SIZE(char, query_len + 1);
    //const char *query = "(objectClass=addr_leased)";
    snprintf(query, query_len + 1, "(objectClass=%s)", a_group);
    int count = 0;
    // Read data
    pthread_mutex_lock(&ldb_mutex);
    pdap_store_obj_t store_obj = dap_db_read_data(query, &count, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    DAP_DELETE(query);
    // Serialization data
    dap_store_obj_pkt_t *pkt = dap_store_packet_multiple(store_obj, 0, count);
    dab_db_free_pdap_store_obj_t(store_obj, count);
    if(pkt)
    {
        int count_new = 0;
        pdap_store_obj_t store_data = dap_store_unpacket(pkt, &count_new);
        assert(count_new == count);
        //char **data = DAP_NEW_SIZE(char*, (count_new + 1) * sizeof(char*));
        dap_global_db_obj_t **data = DAP_NEW_Z_SIZE(dap_global_db_obj_t*,
                (count_new + 1) * sizeof(dap_global_db_obj_t*)); // last item in mass must be zero
        for(int i = 0; i < count_new; i++) {
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
            *a_data_size_out = (size_t) count_new;
        return data;
    }
    if(a_data_size_out)
        *a_data_size_out = 0;
    return NULL;
}

dap_global_db_obj_t** dap_chain_global_db_load(size_t *a_data_size_out)
{
    return dap_chain_global_db_gr_load(GROUP_NAME_DEFAULT, a_data_size_out);
}
/**
 * Write to the database from an array of data_size bytes
 *
 * @return
 */
bool dap_chain_global_db_obj_save(void* a_store_data, size_t a_objs_count)
{
    dap_store_obj_t* l_store_data = (dap_store_obj_t*) a_store_data;
    if(l_store_data && a_objs_count > 0) {
        // real records
        int l_objs_count = a_objs_count;
        const char *l_group = l_store_data[0].group;

        // read data
        for(int i = 0; i < a_objs_count; i++) {
            dap_store_obj_t* l_obj = l_store_data + i;
            int l_count = 0;
            char *l_query = dap_strdup_printf("(&(cn=%s)(objectClass=%s))", l_obj->key, l_obj->group);
            pthread_mutex_lock(&ldb_mutex);
            dap_store_obj_t *l_read_store_data = dap_db_read_data(l_query, &l_count, l_group);
            pthread_mutex_unlock(&ldb_mutex);
            // don't save obj if (present timestamp) > (new timestamp)
            if(l_read_store_data) {
                if(l_count == 1 && l_read_store_data->timestamp >= l_obj->timestamp) {
                    // mark to not save
                    l_obj->timestamp = (time_t) -1;
                    // reduce the number of real records
                    l_objs_count--;
                }
                dab_db_free_pdap_store_obj_t(l_read_store_data, l_count);
            }

            DAP_DELETE(l_query);
        }

        // save data
        if(l_objs_count > 0) {

            pthread_mutex_lock(&ldb_mutex);
            int res = dap_db_add(l_store_data, a_objs_count);
            if(!res && !is_local_group(l_group))
                dap_db_history_add('a', l_store_data, a_objs_count);
            pthread_mutex_unlock(&ldb_mutex);
            if(!res)
                return true;
        }
        else
            return true;
    }
    return false;
}

bool dap_chain_global_db_gr_save(dap_global_db_obj_t* a_objs, size_t a_objs_count, const char *a_group)
{
    dap_store_obj_t *store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, a_objs_count * sizeof(struct dap_store_obj));
    time_t l_timestamp = time(NULL);
    for(size_t q = 0; q < a_objs_count; ++q) {
        dap_store_obj_t *store_data_cur = store_data + q;
        dap_global_db_obj_t *a_obj_cur = a_objs + q;
        store_data_cur->key = a_obj_cur->key;
        store_data_cur->group = (char*) a_group;
        store_data_cur->value = a_obj_cur->value;
        store_data_cur->value_len = a_obj_cur->value_len;
        store_data_cur->timestamp = l_timestamp;
    }
    if(store_data)
    {
        pthread_mutex_lock(&ldb_mutex);
        int res = dap_db_add(store_data, a_objs_count);
        if(!res && !is_local_group(a_group))
            dap_db_history_add('a', store_data, a_objs_count);
        pthread_mutex_unlock(&ldb_mutex);
        DAP_DELETE(store_data); //dab_db_free_pdap_store_obj_t(store_data, a_objs_count);
        if(!res)
            return true;
    }
    return false;
}

bool dap_chain_global_db_save(dap_global_db_obj_t* a_objs, size_t a_objs_count)
{
    return dap_chain_global_db_gr_save(a_objs, a_objs_count, GROUP_NAME_DEFAULT);
}

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size)
{
    if(!data || data_size <= 0)
        return NULL;
    dap_chain_hash_fast_t l_hash;
    dap_hash_fast((uint8_t*) data, data_size, &l_hash);
    size_t a_str_max = (sizeof(l_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_fast_to_str(&l_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL;
    }
    return a_str;
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

