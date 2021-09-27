#pragma once

#include "dap_chain_global_db_driver.h"
#ifdef DAP_CHAIN_GDB_ENGINE_PGSQL
#include "/usr/include/postgresql/libpq-fe.h"
#endif

int dap_db_driver_pgsql_init(const char *a_filename_dir, dap_db_driver_callbacks_t *a_drv_callback);
