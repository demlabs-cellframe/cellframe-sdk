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
 * get entry from
 */
char * dap_chain_global_db_get(const char *a_key)
{
    char *str = NULL;
    int count = 0;
    if(!a_key)
        return NULL;
    int a = strlen("(cn=key2)(objectClass=addr_leased)");
    char query[32 + strlen(a_key)];
    sprintf(query, "(cn=%s)(objectClass=addr_leased)", a_key);
    pdap_store_obj_t store_data = dap_db_read_data(query, &count); //"(objectClass=addr_leased),cn=key1");
    if(count == 1 && store_data && !strcmp(store_data->key, a_key))
        str = (store_data->value) ? strdup(store_data->value) : NULL;
    dab_db_free_pdap_store_obj_t(store_data);
    return str;
}

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

/*
 dap_chain_global_db_load ()
 dap_chain_global_db_save()
 */
