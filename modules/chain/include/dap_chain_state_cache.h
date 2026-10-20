#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dap_global_db.h"
#include "dap_string.h"

#ifdef __cplusplus
extern "C" {
#endif

// String-named facade over the id-addressed dap_chain_state cache: each group is
// one namespace, every access resolves the key to an id once. Node-private (no
// signing, no replication, no MDBX limit); carried by the snapshot.
int dap_chain_state_cache_set(const char *a_group, const char *a_key, const void *a_value, size_t a_value_len);
int dap_chain_state_cache_del(const char *a_group, const char *a_key);
const uint8_t *dap_chain_state_cache_get(const char *a_group, const char *a_key, size_t *a_value_len);
dap_global_db_obj_t *dap_chain_state_cache_get_all(const char *a_group, size_t *a_count);
size_t dap_chain_state_cache_count(const char *a_group);
int dap_chain_state_cache_clear(const char *a_group);
int dap_chain_state_cache_dump_all(dap_string_t *a_out);
int dap_chain_state_cache_load_all(const uint8_t *a_data, size_t a_size);

#ifdef __cplusplus
}
#endif
