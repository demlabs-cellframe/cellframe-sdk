#include <string.h>
#include <stdlib.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include "dap_chain_global_db_hist.h"

#define GROUP_HISTORY "history"

static char* dap_db_history_pack_hist(dap_global_db_hist_t *a_rec)
{
    char *l_ret = dap_strdup_printf("%c\a%d\a%d\a%d", a_rec->type, a_rec->keys_count, a_rec->key, a_rec->group);
    return l_ret;
}

static char* dap_db_history_timestamp()
{
    time_t l_cur_time = time(NULL);
    return dap_strdup_printf("%lld", (uint64_t) l_cur_time);
}

/**
 * Add data to the history log
 */
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, int a_dap_store_count, const char *a_group)
{
    if(a_dap_store_count < 1 || !a_store_obj || !a_group)
        return false;
    dap_global_db_hist_t l_rec;
    l_rec.keys_count = a_dap_store_count;
    l_rec.type = a_type;
    l_rec.group = a_group;
    if(l_rec.keys_count == 1)
        l_rec.key = a_store_obj->key;

    char *l_str = dap_db_history_pack_hist(&l_rec);
    size_t l_str_len = strlen(l_str);
    time(NULL);
    dap_store_obj_t l_store_data;
    l_store_data.key = dap_db_history_timestamp();
    l_store_data.value = (char*) l_str;
    int l_res = dap_db_add(&l_store_data, 1, GROUP_HISTORY);
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
