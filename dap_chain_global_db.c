#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_global_db_pvt.h"
#include "dap_chain_global_db.h"

// for access from several streams
static pthread_mutex_t ldb_mutex = PTHREAD_MUTEX_INITIALIZER;

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
 */

char * dap_chain_global_db_gr_get(const char *a_key, const char *a_group)
{
    char *str = NULL;
    int count = 0;
    if(!a_key)
        return NULL ;
    char query[32 + strlen(a_key)];
    sprintf(query, "(cn=%s)(objectClass=addr_leased)", a_key);
    pthread_mutex_lock(&ldb_mutex);
    pdap_store_obj_t store_data = dap_db_read_data(query, &count, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    if(count == 1 && store_data && !strcmp(store_data->key, a_key))
        str = (store_data->value) ? strdup(store_data->value) : NULL;
    dab_db_free_pdap_store_obj_t(store_data, count);
    return str;
}
char * dap_chain_global_db_get(const char *a_key)
{
    return dap_chain_global_db_gr_get(a_key, GROUP_NAME_DEFAULT);
}

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key, const char *a_value, const char *a_group)
{
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = (char*) a_key;
    store_data->value = (char*) a_value;
    pthread_mutex_lock(&ldb_mutex);
    int res = dap_db_merge(store_data, 1, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    DAP_DELETE(store_data);
    if(!res)
        return true;
    return false;
}

bool dap_chain_global_db_set(const char *a_key, const char *a_value)
{
    return dap_chain_global_db_gr_set(a_key, a_value, GROUP_NAME_DEFAULT);
}
/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group)
{
    char *str = NULL;
    if(!a_key)
        return NULL ;
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = (char*) a_key;
    pthread_mutex_lock(&ldb_mutex);
    int res = dap_db_delete(store_data, 1, a_group);
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
uint8_t* dap_chain_global_db_gr_load(size_t *data_size, const char *a_group)
{
    const char *query = "(objectClass=addr_leased)";
    int count = 0;
    // Read data
    pthread_mutex_lock(&ldb_mutex);
    pdap_store_obj_t store_obj = dap_db_read_data(query, &count, a_group);
    pthread_mutex_unlock(&ldb_mutex);
    // Serialization data
    dap_store_obj_pkt_t *pkt = dap_store_packet_multiple(store_obj, count);
    dab_db_free_pdap_store_obj_t(store_obj, count);
    if(pkt)
    {
        uint8_t *data = DAP_NEW_SIZE(uint8_t, pkt->data_size);
        memcpy(data, pkt->data, pkt->data_size);
        *data_size = pkt->data_size;
        DAP_DELETE(pkt);
        return data;
    }
    return NULL ;
}

uint8_t* dap_chain_global_db_load(size_t *data_size)
{
    return dap_chain_global_db_gr_load(data_size, GROUP_NAME_DEFAULT);
}
/**
 * Write to the database from an array of data_size bytes
 *
 * @param data array wish base dump
 * @param data size of array
 * @return
 */
bool dap_chain_global_db_gr_save(uint8_t* data, size_t data_size, const char *a_group)
{
    int a = sizeof(dap_store_obj_pkt_t);
    int count = 0;
    dap_store_obj_pkt_t *pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t, sizeof(dap_store_obj_pkt_t) + data_size);
    //pkt->count = 0;
    pkt->data_size = data_size;
    memcpy(pkt->data, data, data_size);
    pdap_store_obj_t store_data = dap_store_unpacket(pkt, &count);
    DAP_DELETE(pkt);
    if(store_data)
    {
        pthread_mutex_lock(&ldb_mutex);
        int res = dap_db_merge(store_data, count, a_group);
        pthread_mutex_unlock(&ldb_mutex);
        dab_db_free_pdap_store_obj_t(store_data, count);
        if(!res)
            return true;
    }
    return false;
}

bool dap_chain_global_db_save(uint8_t* data, size_t data_size)
{
    return dap_chain_global_db_gr_save(data, data_size, GROUP_NAME_DEFAULT);
}

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size)
{
    dap_chain_hash_t a_hash;
    dap_hash((char*) data, data_size, a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_SLOW_0);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_to_str(&a_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL ;
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

