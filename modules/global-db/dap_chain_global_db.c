/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
* Copyright  (c) 2019-2020
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

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include "dap_chain_global_db.h"
#include "uthash.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_chain_common.h"
#include "dap_global_db_sync.h"
#include "dap_time.h"

#ifdef WIN32
#include "registry.h"
#include <string.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 120
#endif

#define LOG_TAG "dap_global_db"



static int s_track_history = 0;

int     s_db_drvmode_async ,                                                /* Set a kind of processing requests to DB:                                                                            <> 0 - Async mode should be used */
        s_dap_global_db_debug_more;                                         /* Enable extensible debug output */



/**
 * @brief Deallocates memory of an objs array.
 * @param objs a pointer to the first object of the array
 * @param a_count a number of objects in the array
 * @return (none)
 */
void dap_chain_global_db_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count)
{
dap_global_db_obj_t *l_obj;

    if ( !a_objs || !a_count )                                              /* Sanity checks */
        return;

    for(l_obj = a_objs; a_count--; l_obj++)                                 /* Run over array's elements */
    {
        DAP_DELETE(l_obj->key);
        DAP_DELETE(l_obj->value);
    }

    DAP_DELETE(a_objs);                                                     /* Finaly kill the the array */
}


static inline  void s_clear_sync_grp(void *a_elm)
{
    dap_sync_group_item_t *l_item = (dap_sync_group_item_t *)a_elm;
    DAP_DELETE(l_item->group_mask);
    DAP_DELETE(l_item);
}

/**
 * @brief Deinitialize a database.
 * @note You should call this function at the end.
 * @return (none)
 */
void dap_chain_global_db_deinit(void)
{
    dap_db_driver_deinit();
}

/**
 * @brief Flushes a database cahce to disk.
 * @return 0
 */
int dap_chain_global_db_flush(void)
{
    return  dap_db_driver_flush();
}

/**
 * @brief Gets an object from a database by a_key and a_group arguments.
 * @param a_key an object key string
 * @param a_group a group name string
 * @return If successful, returns a pointer to the item, otherwise NULL.
 */
dap_store_obj_t *dap_chain_global_db_obj_get(const char *a_key, const char *a_group)
{
    size_t l_count = 1;
    // read one item
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_count);
    return l_store_data;
}

/**
 * @brief Gets an array consisting of a_data_len_out objects from a database by a_key and a_group arguments.
 * @param a_key an object key string
 * @param a_data_len_out[in] a number of objects to be gotten, if NULL - no limits
 * @param a_data_len_out[out] a number of objects that were gotten
 * @param a_group a group name string
 * @return If successful, returns a pointer to the first item in the array; otherwise NULL.
 */
dap_store_obj_t* dap_chain_global_db_obj_gr_get(const char *a_key, size_t *a_data_len_out, const char *a_group)
{
    // read several items, 0 - no limits
    size_t l_data_len_out = 0;
    if(a_data_len_out)
        l_data_len_out = *a_data_len_out;
    dap_store_obj_t *l_store_data = dap_chain_global_db_driver_read(a_group, a_key, &l_data_len_out);
    if(l_store_data) {
        if(a_data_len_out)
            *a_data_len_out = l_data_len_out;
    }
    return l_store_data;
}


/**
 * @brief Gets time stamp of the deleted object by a_group and a_key arguments.
 * @param a_group a group name sring, for example "kelvin-testnet.nodes"
 * @param a_key an object key string, looked like "0x8FAFBD00B..."
 * @return If successful, a time stamp, otherwise 0.
 */
uint64_t global_db_gr_del_get_timestamp(const char *a_group, const char *a_key)
{
uint64_t l_timestamp = 0;
dap_store_obj_t store_data = { 0 };
char l_group[DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX];
size_t l_count_out = 0;
dap_store_obj_t *l_obj;

    if(!a_key)
        return l_timestamp;

    store_data.key = a_key;
    dap_snprintf(l_group, sizeof(l_group) - 1,  "%s.del", a_group);
    store_data.group = l_group;

    if (dap_chain_global_db_driver_is(store_data.group, store_data.key))
    {
        if ( (l_obj = dap_chain_global_db_driver_read(store_data.group, store_data.key, &l_count_out)) )
        {
            if ( (l_count_out > 1) )
                log_it(L_WARNING, "Got more then 1 records (%zu) for group '%s'", l_count_out, l_group);

            l_timestamp = l_obj->timestamp;
            dap_store_obj_free(l_obj, l_count_out);
        }
    }

    return l_timestamp;
}



