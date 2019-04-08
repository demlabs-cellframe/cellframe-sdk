#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"

#define GROUP_NODE "addrs_leased"
#define GROUP_ALIAS "aliases_leased"
#define GROUP_DATUM "datums"
#define GROUP_REMOTE_NODE "remote_node"

#define GROUP_NAME_DEFAULT GROUP_DATUM

typedef struct dap_global_db_obj {
    char *key;
    char *value;
    size_t value_len;
}DAP_ALIGN_PACKED dap_global_db_obj_t, *pdap_global_db_obj_t;

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
void dap_chain_global_db_objs_delete(dap_global_db_obj_t **objs);

int dap_chain_global_db_init(dap_config_t * a_config);

void dap_chain_global_db_deinit();

/**
 * Get entry from base
 */
void* dap_chain_global_db_obj_get(const char *a_key, const char *a_group);
uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_out, const char *a_group);
uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_out);

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key, const uint8_t *a_value, size_t a_value_len, const char *a_group);
bool dap_chain_global_db_set(const char *a_key, const uint8_t *a_value, size_t a_value_len);

/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group);
bool dap_chain_global_db_del(const char *a_key);

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_global_db_obj_t** dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out);
dap_global_db_obj_t** dap_chain_global_db_load(size_t *a_data_size_out);

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
uint8_t* dap_db_log_pack(dap_global_db_obj_t *a_obj, int *a_data_size_out);
// Parse data from dap_db_log_pack()
void* dap_db_log_unpack(uint8_t *a_data, int a_data_size, int *a_store_obj_count);
// Get timestamp from dap_db_log_pack()
time_t dap_db_log_unpack_get_timestamp(uint8_t *a_data, int a_data_size);

// Get last timestamp in log
char *dap_db_log_get_last_timestamp(void);
// Get log diff as list
dap_list_t* dap_db_log_get_list(time_t first_timestamp);
// Free list getting from dap_db_log_get_list()
void dap_db_log_del_list(dap_list_t *a_list);
// Get log diff as string
char* dap_db_log_get_diff(size_t *a_data_size_out);
