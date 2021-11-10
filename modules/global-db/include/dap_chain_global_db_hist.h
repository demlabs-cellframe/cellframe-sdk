#pragma once

#include <stdbool.h>
#include <dap_list.h>
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_driver.h"

#define GLOBAL_DB_HIST_REC_SEPARATOR "\r;"
#define GLOBAL_DB_HIST_KEY_SEPARATOR "\a;"

#define F_DB_LOG_ADD_EXTRA_GROUPS   1
#define F_DB_LOG_SYNC_FROM_ZERO     2

typedef struct dap_global_db_hist {
    char type;// 'a' add or 'd' delete
    const char *group;
    size_t keys_count;
    char *keys;
} dap_global_db_hist_t;

//Add data to the history log
bool dap_db_history_add(char a_type, pdap_store_obj_t a_store_obj, size_t a_dap_store_count, const char *a_group);

// for dap_db_log_list_xxx()

typedef struct dap_db_log_list_group {
    char *name;
    uint64_t last_id_synced;
    uint64_t count;
} dap_db_log_list_group_t;

typedef struct dap_db_log_list_obj {
    dap_store_obj_pkt_t *pkt;
    dap_hash_fast_t hash;
} dap_db_log_list_obj_t;

typedef struct dap_db_log_list {
    dap_list_t *list_write; // writed list
    dap_list_t *list_read; // readed list (inside list_write)
    bool is_process;
    size_t items_rest; // rest items to read from list_read
    size_t items_number; // total items in list_write after reading from db
    dap_list_t *groups;
    pthread_t thread;
    pthread_mutex_t list_mutex;
} dap_db_log_list_t;

dap_db_log_list_t* dap_db_log_list_start(dap_chain_node_addr_t a_addr, int flags);
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list);
size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list);
dap_db_log_list_obj_t *dap_db_log_list_get(dap_db_log_list_t *a_db_log_list);
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list);
// Get last id in log
uint64_t dap_db_log_get_group_last_id(const char *a_group_name);
uint64_t dap_db_log_get_last_id(void);

