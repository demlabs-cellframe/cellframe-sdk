#include <string.h>
#include <stdlib.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_hist.h"

#define GROUP_HISTORY "history"

#define HIST_REC_SEPARATOR "\r;"
#define HIST_KEY_SEPARATOR "\a;"

static char* dap_db_history_pack_hist(dap_global_db_hist_t *a_rec)
{
    char *l_ret = dap_strdup_printf("%c%s%d%s%s%s%s", a_rec->type, HIST_REC_SEPARATOR, a_rec->keys_count,
    HIST_REC_SEPARATOR, a_rec->group, HIST_REC_SEPARATOR, a_rec->keys);
    return l_ret;
}

static int dap_db_history_unpack_hist(char *l_str_in, dap_global_db_hist_t *a_rec_out)
{
    char **l_strv = dap_strsplit(l_str_in, HIST_REC_SEPARATOR, -1);
    int l_count = dap_str_countv(l_strv);
    if(l_count != 4)
        return -1;
    a_rec_out->type = l_strv[0][0];
    a_rec_out->keys_count = strtod(l_strv[1], NULL);
    a_rec_out->group = dap_strdup(l_strv[2]);
    a_rec_out->keys = dap_strdup(l_strv[3]);
    dap_strfreev(l_strv);
    return 1;
}

static char* dap_db_history_timestamp()
{
    time_t l_cur_time = time(NULL);
    return dap_strdup_printf("%lld", (uint64_t) l_cur_time);
}

/**
 * Add data to the history log
 */
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, int a_dap_store_count)
{
    if(!a_store_obj || a_dap_store_count <= 0)
        return false;
    dap_global_db_hist_t l_rec;
    l_rec.keys_count = a_dap_store_count;
    l_rec.type = a_type;
    if(l_rec.keys_count >= 1)
        l_rec.group = a_store_obj->group;
    if(l_rec.keys_count == 1)
        l_rec.keys = a_store_obj->key;
    else {
        // make keys vector
        char **l_keys = DAP_NEW_SIZE(char*, sizeof(char*) * (a_dap_store_count + 1));
        int i;
        for(i = 0; i < a_dap_store_count; i++) {
            l_keys[i] = a_store_obj[i].key;
        }
        l_keys[i] = NULL;
        l_rec.keys = dap_strjoinv(HIST_KEY_SEPARATOR, l_keys);
        DAP_DELETE(l_keys);
    }

    char *l_str = dap_db_history_pack_hist(&l_rec);
    size_t l_str_len = strlen(l_str);
    dap_store_obj_t l_store_data;
    // key - timestamp
    // value - keys of added/deleted data
    l_store_data.key = dap_db_history_timestamp();
    l_store_data.value = (char*) l_str;
    l_store_data.group = GROUP_HISTORY;
    int l_res = dap_db_add(&l_store_data, 1);
    if(l_rec.keys_count > 1)
        DAP_DELETE(l_rec.keys);
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

/**
 * Get log diff
 */
char* dap_db_log_get_diff(size_t *a_data_size_out)
{
    //DapList *l_group_list = dap_list_append(l_group_list,GROUP_HISTORY);
    size_t l_data_size_out = 0;
    dap_global_db_obj_t **l_objs = dap_chain_global_db_gr_load(GROUP_HISTORY, &l_data_size_out);
    // make keys & val vector
    char **l_keys_vals0 = DAP_NEW_SIZE(char*, sizeof(char*) * (l_data_size_out * 2 + 2));
    char **l_keys_vals = l_keys_vals0 + 1;
    int i;
    // first element - number of records
    l_keys_vals0[0] = dap_strdup_printf("%d", l_data_size_out);
    for(i = 0; i < l_data_size_out; i++) {
        dap_global_db_obj_t *l_obj_cur = l_objs[i];
        l_keys_vals[i] = l_obj_cur->key;
        l_keys_vals[i + l_data_size_out] = l_obj_cur->value;
    }
    // last element - NULL (marker)
    l_keys_vals[l_data_size_out * 2] = NULL;
    char *l_keys_vals_flat = dap_strjoinv(HIST_KEY_SEPARATOR, l_keys_vals0);
    DAP_DELETE(l_keys_vals0[0]);
    DAP_DELETE(l_keys_vals0);
    //dap_strfreev(l_keys_vals0);
    dap_chain_global_db_objs_delete(l_objs);
    return l_keys_vals_flat;
}

