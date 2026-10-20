#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dap_common.h"
#include "dap_global_db.h"

#ifdef __cplusplus
extern "C" {
#endif

// Local (node-private) key/value groups for service caches and registries.
// Unlike the GlobalDB they are not signed, not replicated and have no MDBX size
// limit; the snapshot carries them across restarts, so a start without a chain
// scan restores them directly. GDB stays for state that must be shared between
// nodes (decrees/policies/cluster data).

int dap_local_state_set(const char *a_group, const char *a_key, const void *a_value, size_t a_value_len);
int dap_local_state_del(const char *a_group, const char *a_key);
// Returns the stored value (owned by the store) or NULL.
const uint8_t *dap_local_state_get(const char *a_group, const char *a_key, size_t *a_value_len);
// Returns a malloc'd array compatible with dap_global_db_objs_delete(); the caller
// frees it with that function (or dap_local_state_objs_delete).
dap_global_db_obj_t *dap_local_state_get_all(const char *a_group, size_t *a_count);
void dap_local_state_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count);
size_t dap_local_state_count(const char *a_group);
// Drops every entry of the group (cache reset).
int dap_local_state_clear(const char *a_group);

// Snapshot section payload: every group and entry in one buffer.
int dap_local_state_dump(dap_string_t *a_out);
int dap_local_state_load(const uint8_t *a_data, size_t a_size);

#ifdef __cplusplus
}
#endif
