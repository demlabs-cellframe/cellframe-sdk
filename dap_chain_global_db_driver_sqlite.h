/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sqlite3.h"
#include "dap_chain_global_db_driver.h"

int dap_db_driver_sqlite_init(const char *a_filename_db, dap_db_driver_callbacks_t *a_drv_callback);
int dap_db_driver_sqlite_deinit(void);

sqlite3* dap_db_driver_sqlite_open(const char *a_filename_utf8, int a_flags, char **error_message);
void dap_db_driver_sqlite_close(sqlite3 *l_db);
void dap_db_driver_sqlite_free(char *memory);
bool dap_db_driver_sqlite_set_pragma(sqlite3 *a_db, char *a_param, char *a_mode);


// ** SQLite callbacks **

// Start a transaction
int dap_db_driver_sqlite_start_transaction(void);
// End of transaction
int dap_db_driver_sqlite_end_transaction(void);

// Apply data (write or delete)
int dap_db_driver_sqlite_apply_store_obj(dap_store_obj_t *a_store_obj);
// Read data
dap_store_obj_t* dap_db_driver_sqlite_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out);
