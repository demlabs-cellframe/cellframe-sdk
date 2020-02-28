#pragma once

#include <stdbool.h>
#include <dap_list.h>
#include "dap_chain_global_db.h"
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


// for dap_db_log_list_xxx()
typedef struct dap_db_log_list {
    dap_list_t *list_write; // writed list
    dap_list_t *list_read;  // readed list (inside list_write)
    bool is_process;
    size_t item_start;
    size_t item_last;
    size_t items_rest;
    size_t items_number;
    pthread_t thread;
    pthread_mutex_t list_mutex;
} dap_db_log_list_t;

dap_db_log_list_t* dap_db_log_list_start(uint64_t first_id);
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list);
size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list);
dap_global_db_obj_t* dap_db_log_list_get(dap_db_log_list_t *a_db_log_list);
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list);

