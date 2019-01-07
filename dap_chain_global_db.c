#include "dap_chain_global_db_pvt.h"

#include <string.h>
#include <stdio.h>

int dap_chain_global_db_init(const char *a_storage_path)
{
    if(a_storage_path)
    {
        int res = dap_db_init(a_storage_path);
        return res;
    }
    return -1;
}

void dap_chain_global_db_deinit(void)
{
    dap_db_deinit();
}

/**
 * Get entry from base
 */
char * dap_chain_global_db_get(const char *a_key)
{
    char *str = NULL;
    int count = 0;
    if(!a_key)
        return NULL;
    char query[32 + strlen(a_key)];
    sprintf(query, "(cn=%s)(objectClass=addr_leased)", a_key);
    pdap_store_obj_t store_data = dap_db_read_data(query, &count);
    if(count == 1 && store_data && !strcmp(store_data->key, a_key))
        str = (store_data->value) ? strdup(store_data->value) : NULL;
    dab_db_free_pdap_store_obj_t(store_data, count);
    return str;
}

/**
 * Set one entry to base
 */
bool dap_chain_global_db_set(const char *a_key, const char *a_value)
{
    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(struct dap_store_obj));
    store_data->key = (char*) a_key;
    store_data->value = (char*) a_value;
    int res = dap_db_merge(store_data, 1);
    DAP_DELETE(store_data);
    if(!res)
        return true;
    return false;
}

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
uint8_t* dap_chain_global_db_load(size_t *data_size)
{
    const char *query = "(objectClass=addr_leased)";
    int count = 0;
    // Read data
    pdap_store_obj_t store_obj = dap_db_read_data(query, &count);
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
    return NULL;
}

/**
 * Write to the database from an array of data_size bytes
 *
 * @param data array wish base dump
 * @param data size of array
 * @return
 */
bool dap_chain_global_db_save(uint8_t* data, size_t data_size)
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
        int res = dap_db_merge(store_data, count);
        dab_db_free_pdap_store_obj_t(store_data, count);
        if(!res)
            return true;
    }
    return false;
}

