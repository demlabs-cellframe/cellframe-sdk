#pragma once

#include <stdbool.h>

#include "dap_chain_global_db_pvt.h"

typedef struct dap_global_db_hist_t {
    int keys_count;
    char *key;
    char type;// add or delete
    const char *group;
} dap_global_db_hist_t;

//Add data to the history log
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, int a_dap_store_count, const char *a_group);

// Truncate the history log
bool dap_db_history_truncate(void);
