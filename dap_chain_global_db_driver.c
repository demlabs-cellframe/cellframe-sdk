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

#include <stddef.h>
#include <stdint.h>
#include "dap_common.h"
#include "dap_strfuncs.h"

#include "dap_chain_global_db_driver_sqlite.h"
#include "dap_chain_global_db_driver.h"

static char *s_used_driver = NULL;
/**
 * Select driver
 * driver_name may be "ldb", "sqlite"
 *
 * return 0 OK, <0 Error
 */
int dap_db_driver_init(const char *a_driver_name, const char *a_filename_db)
{
    if(s_used_driver)
        dap_db_driver_deinit();
    s_used_driver = dap_strdup(a_driver_name);
    if(!dap_strcmp(s_used_driver, "ldb"))
        return -1;
    if(!dap_strcmp(s_used_driver, "sqlite"))
        return dap_db_driver_sqlite_init(a_filename_db);
    return -1;
}

/**
 * Shutting down the db library
 */

void dap_db_driver_deinit(void)
{
//    if(!dap_strcmp(s_used_driver, "ldb"))
//        ;
    if(!dap_strcmp(s_used_driver, "sqlite"))
        dap_db_driver_sqlite_deinit();
    DAP_DELETE(s_used_driver);
    s_used_driver = NULL;
}

