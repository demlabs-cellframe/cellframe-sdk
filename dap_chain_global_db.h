#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_config.h"

#define GROUP_NODE "addrs_leased"
#define GROUP_ALIAS "aliases_leased"
#define GROUP_DATUM "datums"

#define GROUP_NAME_DEFAULT GROUP_DATUM

typedef struct dap_global_db_obj {
    char *key;
    char *value;
}DAP_ALIGN_PACKED dap_global_db_obj_t, *pdap_global_db_obj_t;

/**
 * Clean struct dap_global_db_obj_t
 */
void dap_chain_global_db_obj_clean(dap_global_db_obj_t *obj);

/**
 * Delete mass of struct dap_global_db_obj_t
 */
void dap_chain_global_db_objs_delete(dap_global_db_obj_t **objs);

int dap_chain_global_db_init(dap_config_t * a_config);

void dap_chain_global_db_deinit();

/**
 * Get entry from base
 */
char * dap_chain_global_db_gr_get(const char *a_key, const char *a_group);
char* dap_chain_global_db_get(const char *a_key);

/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set(const char *a_key, const char *a_value, const char *a_group);
bool dap_chain_global_db_set(const char *a_key, const char *a_value);

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
dap_global_db_obj_t** dap_chain_global_db_gr_load(size_t *data_size, const char *a_group);
dap_global_db_obj_t** dap_chain_global_db_load(size_t *data_size);

/**
 * Write to the database from an array of data_size bytes
 *
 * @param data array wish base dump
 * @param data size of array
 * @return
 */
bool dap_chain_global_db_gr_save(uint8_t* data, size_t data_size, const char *a_group);
bool dap_chain_global_db_save(uint8_t* data, size_t data_size);

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_hash(const uint8_t *data, size_t data_size);
char* dap_chain_global_db_hash_fast(const uint8_t *data, size_t data_size);

