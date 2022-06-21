#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "dap_chain_global_db_driver.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_global_db.h"
#include "dap_global_db_sync.h"

#define GROUP_LOCAL_NODE_LAST_ID    "local.node.last_id"
#define GROUP_LOCAL_NODE_ADDR       "local.node-addr"

#define DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX      128                                     /* A maximum size of group name */
#define DAP_GLOBAL_DB_GROUPS_COUNT_MAX          1024                                    /* A maximum number of groups */
#define DAP_GLOBAL_DB_KEY_MAX            512                                     /* A limit for the key's length in DB */
#define DAP_GLOBAL_DB_MAX_OBJS            8192          /* A maximum number of objects to be returned by
                                                                            read_srore_obj() */

enum    {
    DAP_DB$K_OPTYPE_ADD  = 0x61,    /* 'a', */                              /* Operation Type = INSERT/ADD */
    DAP_DB$K_OPTYPE_DEL  = 0x64,    /* 'd', */                              /*  -- // -- DELETE */
    DAP_DB$K_OPTYPE_RETR = 0x72,    /* 'r', */                              /*  -- // -- RETRIEVE/GET */
};


/**
 * Get entry from base
 */
dap_store_obj_t *dap_chain_global_db_obj_get(const char *a_key, const char *a_group);
dap_store_obj_t* dap_chain_global_db_obj_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group);
uint8_t* dap_chain_global_db_gr_get_ext(const char *a_key, size_t *a_data_len_out, const char *a_group, uint8_t *a_flags_out);
uint8_t * dap_chain_global_db_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group);
uint8_t * dap_chain_global_db_get(const char *a_key, size_t *a_data_len_out);


/**
 * Set one entry to base
 */
bool dap_chain_global_db_gr_set_ext(const char *a_key, const void *a_value, size_t a_value_len, const char *a_group, uint8_t a_flags);
bool dap_chain_global_db_gr_set(const char *a_key,  const void *a_value, size_t a_value_len, const char *a_group);
bool dap_chain_global_db_pinned_gr_set(const char *a_key, const void *a_value, size_t a_value_len, const char *a_group);
bool dap_chain_global_db_set(const char *a_key, const void *a_value, size_t a_value_len);

/**
 * Delete entry from base
 */
bool dap_chain_global_db_gr_del(const char *a_key, const char *a_group);
bool dap_chain_global_db_del(char *a_key);

/**
 * Get timestamp of the deleted entry
 */
uint64_t global_db_gr_del_get_timestamp(const char *a_group, const char *a_key);

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
dap_store_obj_t* dap_chain_global_db_get_last(const char *a_group);
dap_global_db_obj_t* dap_chain_global_db_gr_load(const char *a_group, size_t *a_data_size_out);
