#pragma once

#include <stdbool.h>
#include "dap_chain_global_db_driver.h"

#define GLOBAL_DB_HIST_REC_SEPARATOR "\r;"
#define GLOBAL_DB_HIST_KEY_SEPARATOR "\a;"

typedef struct dap_global_db_hist {
    char type;// 'a' add or 'd' delete
    const char *group;
    size_t keys_count;
    char *keys;
} dap_global_db_hist_t;

//Add data to the history log
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, size_t a_dap_store_count);

// Truncate the history log
bool dap_db_history_truncate(void);

