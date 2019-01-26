#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_config.h"

int dap_chain_global_db_init(dap_config_t * a_config);

void dap_chain_global_db_deinit();

/**
 * Get entry from base
 */
char* dap_chain_global_db_get(const char *a_key);

/**
 * Set one entry to base
 */
bool dap_chain_global_db_set(const char *a_key, const char *a_value);

/**
 * Delete entry from base
 */
bool dap_chain_global_db_del(const char *a_key);

/**
 * Read the entire database into an array of size bytes
 *
 * @param data_size[out] size of output array
 * @return array (note:not Null-terminated string) on NULL in case of an error
 */
uint8_t* dap_chain_global_db_load(size_t *data_size);

/**
 * Write to the database from an array of data_size bytes
 *
 * @param data array wish base dump
 * @param data size of array
 * @return
 */
bool dap_chain_global_db_save(uint8_t* data, size_t data_size);
