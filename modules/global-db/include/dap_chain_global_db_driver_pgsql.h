#pragma once

#include "dap_chain_global_db_driver.h"
#ifdef DAP_CHAIN_GDB_ENGINE_PGSQL
#include "/usr/include/postgresql/libpq-fe.h"
#endif

#define DAP_PGSQL_DBHASHNAME_LEN    8
#define DAP_PGSQL_POOL_COUNT        16
#define PGSQL_INVALID_TABLE         "42P01"

int dap_db_driver_pgsql_init(const char *a_filename_dir, dap_db_driver_callbacks_t *a_drv_callback);
int dap_db_driver_pgsql_deinit();
int dap_db_driver_pgsql_start_transaction(void);
int dap_db_driver_pgsql_end_transaction(void);
int dap_db_driver_pgsql_apply_store_obj(dap_store_obj_t *a_store_obj);
dap_store_obj_t *dap_db_driver_pgsql_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out);
dap_store_obj_t *dap_db_driver_pgsql_read_last_store_obj(const char *a_group);
dap_store_obj_t *dap_db_driver_pgsql_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out);
dap_list_t *dap_db_driver_pgsql_get_groups_by_mask(const char *a_group_mask);
size_t dap_db_driver_pgsql_read_count_store(const char *a_group, uint64_t a_id);
bool dap_db_driver_pgsql_is_obj(const char *a_group, const char *a_key);
int dap_db_driver_pgsql_flush();
