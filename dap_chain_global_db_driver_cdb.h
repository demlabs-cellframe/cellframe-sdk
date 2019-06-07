/*
 * Authors:
 * Konstantin Papizh <konstantin.papizh@demlabs.net>
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

#include "cuttdb.h"
#include "dap_chain_global_db_driver.h"

typedef struct _cdb_options {
    int hsize;      // Main hash table size, 1%-10% of total records, immutable
    int rcacheMB;   // Record cache in MBytes
    int pcacheMB;   // Index page cache in MBytes
} cdb_options, *pcdb_options;

typedef struct _cdb_record {
    char *key;
    char *val;
} cdb_record, *pcdb_record;

int dap_db_driver_cdb_init(const char*, dap_db_driver_callbacks_t*);
int dap_db_driver_cdb_deinit();

int dap_db_driver_cdb_apply_store_obj(pdap_store_obj_t);

dap_store_obj_t *dap_db_driver_cdb_read_last_store_obj(const char*);
dap_store_obj_t *dap_db_driver_cdb_read_store_obj(const char*, const char*, size_t*);
dap_store_obj_t* dap_db_driver_cdb_read_cond_store_obj(const char*, uint64_t, size_t*);
