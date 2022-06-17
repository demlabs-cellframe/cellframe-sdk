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

    MODIFICATION HISTORY:
        08-MAY-2022 RRL Added <ctx> field to the DB Driver interface table is called as <dap_db_driver_callbacks_t>;
                        a set of limits - see DAP$K/SZ constant definitions;
                        added lengths for the character fields.
 */

#pragma once

#include "dap_time.h"
#include "dap_list.h"
#include "dap_global_db.h"
#include <stddef.h>
#include <stdint.h>

#define DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX     128                                      /* A maximum size of group name */
#define DAP_GLOBAL_DB_GROUPS_COUNT_MAX         1024                                     /* A maximum number of groups */
#define DAP_GLOBAL_DB_KEY_MAX           512                                      /* A limit for the key's length in DB */
#define DAP_GLOBAL_DB_MAX_OBJS            8192                                    /* A maximum number of objects to be returned by
                                                                            read_srore_obj() */

enum RECORD_FLAGS {
    RECORD_COMMON = 0,    // 0000
    RECORD_PINNED = 1,    // 0001
};


typedef struct dap_store_obj_pkt {
    dap_nanotime_t timestamp;
    uint64_t data_size;
    uint32_t obj_count;
    uint8_t data[];
}__attribute__((packed)) dap_store_obj_pkt_t;

typedef int (*dap_db_driver_write_callback_t)(dap_store_obj_t*);
typedef dap_store_obj_t* (*dap_db_driver_read_callback_t)(const char *,const char *, size_t *);
typedef dap_store_obj_t* (*dap_db_driver_read_cond_callback_t)(const char *,uint64_t , size_t *);
typedef dap_store_obj_t* (*dap_db_driver_read_last_callback_t)(const char *);
typedef size_t (*dap_db_driver_read_count_callback_t)(const char *,uint64_t);
typedef dap_list_t* (*dap_db_driver_get_groups_callback_t)(const char *);
typedef bool (*dap_db_driver_is_obj_callback_t)(const char *, const char *);
typedef int (*dap_db_driver_callback_t)(void);

typedef struct dap_db_driver_callbacks {
    dap_db_driver_write_callback_t      apply_store_obj;                    /* Performs an DB's action like: INSERT/DELETE/UPDATE for the given
                                                                              'store object' */
    dap_db_driver_read_callback_t       read_store_obj;                     /* Retreive 'store object' from DB */
    dap_db_driver_read_last_callback_t  read_last_store_obj;
    dap_db_driver_read_cond_callback_t  read_cond_store_obj;
    dap_db_driver_read_count_callback_t read_count_store;

    dap_db_driver_get_groups_callback_t get_groups_by_mask;                 /* Return a list of tables/groups has been matched to pattern */

    dap_db_driver_is_obj_callback_t     is_obj;                             /* Check for existence of a record in the table/group for
                                                                              a given <key> */

    dap_db_driver_callback_t            transaction_start;                  /* Allocate DB context for consequtive operations */
    dap_db_driver_callback_t            transaction_end;                    /* Release DB context at end of DB consequtive operations */

    dap_db_driver_callback_t            deinit;
    dap_db_driver_callback_t            flush;
} dap_db_driver_callbacks_t;


int     dap_db_driver_init(const char *driver_name, const char *a_filename_db, int a_mode_async);
void    dap_db_driver_deinit(void);

dap_store_obj_t* dap_store_obj_copy(dap_store_obj_t *a_store_obj, size_t a_store_count);
void    dap_store_obj_free(dap_store_obj_t *a_store_obj, size_t a_store_count);
DAP_STATIC_INLINE void dap_store_obj_free_one(dap_store_obj_t *a_store_obj) { return dap_store_obj_free(a_store_obj, 1); }
int     dap_db_driver_flush(void);

int dap_chain_global_db_driver_apply(dap_store_obj_t *a_store_obj, size_t a_store_count);
int dap_chain_global_db_driver_add(pdap_store_obj_t a_store_obj, size_t a_store_count);
int dap_chain_global_db_driver_delete(pdap_store_obj_t a_store_obj, size_t a_store_count);
dap_store_obj_t* dap_chain_global_db_driver_read_last(const char *a_group);
dap_store_obj_t* dap_chain_global_db_driver_cond_read(const char *a_group, uint64_t id, size_t *a_count_out);
dap_store_obj_t* dap_chain_global_db_driver_read(const char *a_group, const char *a_key, size_t *count_out);
bool dap_chain_global_db_driver_is(const char *a_group, const char *a_key);
size_t dap_chain_global_db_driver_count(const char *a_group, uint64_t id);
dap_list_t* dap_chain_global_db_driver_get_groups_by_mask(const char *a_group_mask);
