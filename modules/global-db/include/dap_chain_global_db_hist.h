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
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, size_t a_dap_store_count, const char *a_group);

// Truncate the history log
bool dap_db_history_truncate(void);


// for dap_db_log_list_xxx()
typedef struct dap_db_log_list {
    dap_list_t *list_write; // writed list
    dap_list_t *list_read; // readed list (inside list_write)
    bool is_process;
    size_t item_start; // first item to read from db
    size_t item_last; // last item to read from db
    size_t items_rest; // rest items to read from list_read
    size_t items_number_main;
    size_t items_number_add;
    size_t items_number; // remaining items in list_write after reading from db
    char **group_names;
    int64_t group_number; // number of group
    int64_t group_cur; // current group number, -1 for the main group, 0 ... group_count for the additional group
    size_t *group_number_items; // number of items for each group
    uint64_t *group_last_id;
    dap_list_t *add_groups; // additional group for sync
    pthread_t thread;
    pthread_mutex_t list_mutex;
} dap_db_log_list_t;

dap_db_log_list_t* dap_db_log_list_start(uint64_t first_id, dap_list_t *a_add_groups);
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list);
size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list);
dap_global_db_obj_t* dap_db_log_list_get(dap_db_log_list_t *a_db_log_list);
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list);

