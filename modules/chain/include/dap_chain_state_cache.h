#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_string.h"

#ifdef __cplusplus
extern "C" {
#endif

// String-named facade over the id-addressed dap_chain_state cache: each group is
// one namespace, every access resolves the key to an id once. Node-private (no
// signing, no replication, no MDBX limit); carried by the snapshot.
int dap_chain_state_cache_set(const char *a_group, const char *a_key, const void *a_value, size_t a_value_len);
// Binary-key entry: the id comes from the key bytes themselves (no string
// formatting at the call site); the key bytes are stored as the value when
// a_value is NULL, so the caller keeps only the id on the hot path.
int dap_chain_state_cache_set_bin(const char *a_group, const void *a_key, size_t a_key_len,
                                  const void *a_value, size_t a_value_len);
int dap_chain_state_cache_del(const char *a_group, const char *a_key);
const uint8_t *dap_chain_state_cache_get(const char *a_group, const char *a_key, size_t *a_value_len);
dap_global_db_obj_t *dap_chain_state_cache_get_all(const char *a_group, size_t *a_count);
// Raw (dap_store_obj_t) view for code written against the GlobalDB raw API.
dap_store_obj_t *dap_chain_state_cache_get_all_raw(const char *a_group, size_t *a_count);
void dap_chain_state_cache_raw_free(dap_store_obj_t *a_objs, size_t a_count);
size_t dap_chain_state_cache_count(const char *a_group);
int dap_chain_state_cache_clear(const char *a_group);
int dap_chain_state_cache_dump_all(dap_string_t *a_out);
int dap_chain_state_cache_load_all(const uint8_t *a_data, size_t a_size);

#ifdef __cplusplus
}
#endif
