#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_chain_global_db_driver.h"


#define GROUP_LOCAL_HISTORY "local.history"
#define GROUP_LOCAL_NODE_LAST_ID "local.node.last_id"
#define GROUP_LOCAL_GENERAL "local.general"
#define GROUP_LOCAL_NODE_ADDR "local.node-addr"

typedef struct dap_global_db_obj {
    uint64_t id;
    char *key;
    uint8_t *value;
    size_t value_len;
}DAP_ALIGN_PACKED dap_global_db_obj_t, *pdap_global_db_obj_t;

typedef void (*dap_global_db_obj_callback_notify_t) (void * a_arg, const char a_op_code, const char * a_prefix, const char * a_group,
                                                     const char * a_key, const void * a_value,
                                                     const size_t a_value_len);

/**
 * Flush DB
 */
int dap_chain_global_db_flush(void);

/**
 * Clean struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_clean(dap_global_db_obj_t *obj);
/**
 * Delete struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_delete(dap_global_db_obj_t *obj);

/**
 * Delete mass of struct dap_global_db_obj_t
 */
void dap_chain_global_db_objs_delete(dap_global_db_obj_t *objs, size_t a_count);

int dap_chain_global_db_init(dap_config_t * a_config);

void dap_chain_global_db_deinit(void);

/*
 * Get history group by group name
 */
char* dap_chain_global_db_get_history_group_by_group_name(const char * a_group_name);

/**
 * Setup callbacks and filters
 */
// Add group prefix that will be tracking all changes
void dap_chain_global_db_add_history_group_prefix(const char * a_group_prefix, const char * a_group_name_for_history);
void dap_chain_global_db_add_history_callback_notify(const char * a_group_prefix,
                                                     dap_global_db_obj_callback_notify_t a_callback, void * a_arg);
const char* dap_chain_global_db_add_history_extra_group(const char * a_group_name, dap_chain_node_addr_t *a_nodes, uint16_t *a_nodes_count);
void dap_chain_global_db_add_history_extra_group_callback_notify(const char * a_group_prefix,
        dap_global_db_obj_callback_notify_t a_callback, void * a_arg);
/**
 * Get entry from base
 */
void* dap_chain_global_db_obj_get(const char *a_key, const char *a_group);
dap_store_obj_t* dap_chain_global_db_obj_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group);
uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_out, const char *a_group);
uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_out);

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(char *a_key,  void *a_value, size_t a_value_len, const char *a_group);
bool dap_chain_global_db_set( char *a_key, void *a_value, size_t a_value_len);

/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(char *a_key, const char *a_group);
bool dap_chain_global_db_del(char *a_key);

/**
 * Get timestamp of the deleted entry
 */
time_t global_db_gr_del_get_timestamp(const char *a_group, char *a_key);

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_store_obj_t* dap_chain_global_db_get_last(const char *a_group);
dap_store_obj_t* dap_chain_global_db_cond_load(const char *a_group, uint64_t a_first_id, size_t *a_objs_count);
dap_global_db_obj_t* dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out);
dap_global_db_obj_t* dap_chain_global_db_load(size_t *a_data_size_out);

/**
 * Write to the database from an array of data_size bytes
 *
 * @return
 */
bool dap_chain_global_db_obj_save(void* a_store_data, size_t a_objs_count);
bool dap_chain_global_db_gr_save(dap_global_db_obj_t* a_objs, size_t a_objs_count, const char *a_group);
bool dap_chain_global_db_save(dap_global_db_obj_t* a_objs, size_t a_objs_count);
/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size);
char* dap_chain_global_db_hash_fast(const uint8_t *data, size_t data_size);

// Get data according the history log
dap_list_t* dap_db_log_pack(dap_global_db_obj_t *a_obj, size_t *a_data_size_out);

// Get data according the history log
//char* dap_db_history_tx(dap_chain_hash_fast_t * a_tx_hash, const char *a_group_mempool);
//char* dap_db_history_addr(dap_chain_addr_t * a_addr, const char *a_group_mempool);
//char* dap_db_history(dap_chain_addr_t * a_addr, const char *a_group_mempool);

// Parse data from dap_db_log_pack()
void* dap_db_log_unpack(const void *a_data, size_t a_data_size, size_t *a_store_obj_count);
// Get timestamp from dap_db_log_pack()
//time_t dap_db_log_unpack_get_timestamp(uint8_t *a_data, size_t a_data_size);

// Get last id in log
uint64_t dap_db_log_get_group_history_last_id(const char *a_history_group_name);
uint64_t dap_db_log_get_last_id(void);
// Get log diff as list
dap_list_t* dap_db_log_get_list(uint64_t first_id);
// Free list getting from dap_db_log_get_list()
void dap_db_log_del_list(dap_list_t *a_list);
// Get log diff as string
char* dap_db_log_get_diff(size_t *a_data_size_out);
