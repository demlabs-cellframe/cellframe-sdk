#pragma once

#include <stdbool.h>
#include "dap_chain_global_db_pvt.h"

typedef struct dap_global_db_hist_t {
    char type;// 'a' add or 'd' delete
    const char *group;
    int keys_count;
    char *keys;
} dap_global_db_hist_t;

//Add data to the history log
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, int a_dap_store_count);

// Truncate the history log
bool dap_db_history_truncate(void);

