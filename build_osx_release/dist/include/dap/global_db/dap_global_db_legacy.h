#pragma once

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_global_db_driver.h"
#include "dap_global_db.h"

typedef struct dap_global_db_pkt_old {
    dap_nanotime_t timestamp;
    uint64_t data_size;
    uint32_t obj_count;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_global_db_pkt_old_t;

typedef struct dap_global_db_legacy_list_group {
    char *name;
    uint64_t count;
} dap_global_db_legacy_list_group_t;

typedef struct dap_global_db_legacy_list {
    dap_list_t *groups;
    dap_global_db_driver_hash_t current_hash;
    size_t items_number;
    size_t items_rest;
    dap_list_t *current_group;
} dap_global_db_legacy_list_t;

dap_global_db_pkt_old_t *dap_global_db_pkt_pack_old(dap_global_db_pkt_old_t *a_old_pkt, dap_global_db_pkt_old_t *a_new_pkt);
dap_global_db_pkt_old_t *dap_global_db_pkt_serialize_old(dap_store_obj_t *a_store_obj);
dap_store_obj_t *dap_global_db_pkt_deserialize_old(const dap_global_db_pkt_old_t *a_pkt, size_t *a_store_obj_count);

dap_global_db_legacy_list_t *dap_global_db_legacy_list_start(const char *a_net_name);
dap_list_t *dap_global_db_legacy_list_get_multiple(dap_global_db_legacy_list_t *a_db_legacy_list, size_t a_number_limit);
void dap_global_db_legacy_list_delete(dap_global_db_legacy_list_t *a_db_legacy_list);
DAP_STATIC_INLINE void dap_global_db_legacy_list_rewind(dap_global_db_legacy_list_t *a_db_legacy_list)
{
    a_db_legacy_list->current_group = a_db_legacy_list->groups;
    a_db_legacy_list->items_rest = a_db_legacy_list->items_number;
}
