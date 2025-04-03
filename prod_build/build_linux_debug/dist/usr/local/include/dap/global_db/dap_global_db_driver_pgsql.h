#pragma once

#include "dap_global_db_driver.h"

#define PGSQL_INVALID_TABLE         "42P01"

int dap_global_db_driver_pgsql_init(const char *a_db_conn_info, dap_global_db_driver_callbacks_t *a_drv_callback);

