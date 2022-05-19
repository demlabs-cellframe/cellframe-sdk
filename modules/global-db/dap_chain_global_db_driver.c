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
 *
 *  MODIFICATION HISTORY:
 *
 *      24-FEB-2022 RRL Added Async I/O functionality for DB request processing
 *
 *      15-MAR-2022 RRL Some cosmetic changes to reduce a diagnostic output.
 */

#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "dap_worker.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_proc_queue.h"
#include "dap_events.h"
#include "dap_list.h"
#include "dap_common.h"

#include "dap_chain_global_db_driver_sqlite.h"
#include "dap_chain_global_db_driver_cdb.h"
#include "dap_chain_global_db_driver_mdbx.h"
#include "dap_chain_global_db_driver_pgsql.h"
#include "dap_chain_global_db_driver.h"

#define LOG_TAG "db_driver"

// A selected database driver.
static char s_used_driver [32];                                             /* Name of the driver */


static dap_db_driver_callbacks_t s_drv_callback;                            /* A set of interface routines for the selected
                                                                            DB Driver at startup time */

extern  int s_db_drvmode_async ,                                            /* Set a kind of processing requests to DB:
                                                                            <> 0 - Async mode should be used */
        s_dap_global_db_debug_more;                                         /* Enable extensible debug output */

static pthread_mutex_t s_db_reqs_list_lock = PTHREAD_MUTEX_INITIALIZER;     /* Lock to coordinate access to the <s_db_reqs_queue> */
static dap_slist_t s_db_reqs_list = {0};                                    /* A queue of request to DB - maintained in */


/**
 * @brief Initializes a database driver.
 * @note You should Call this function before using the driver.
 * @param driver_name a string determining a type of database driver:
 * "сdb", "sqlite" ("sqlite3") or "pgsql"
 * @param a_filename_db a path to a database file
 * @return Returns 0, if successful; otherwise <0.
 */
int dap_db_driver_init(const char *a_driver_name, const char *a_filename_db, int a_mode_async)
{
int l_ret = -1;

    if (s_used_driver[0] )
        dap_db_driver_deinit();

    s_db_drvmode_async = a_mode_async;

    // Fill callbacks with zeros
    memset(&s_drv_callback, 0, sizeof(dap_db_driver_callbacks_t));

    if ( s_db_drvmode_async )                                               /* Set a kind of processing requests to DB: <> 0 - Async mode should be used */
    {
        s_db_reqs_list.head = s_db_reqs_list.tail = NULL;
        s_db_reqs_list.nr = 0;
    }

    // Setup driver name
    strncpy( s_used_driver, a_driver_name, sizeof(s_used_driver) - 1);

    dap_mkdir_with_parents(a_filename_db);

    // Compose path
    char l_db_path_ext[strlen(a_driver_name) + strlen(a_filename_db) + 6];
    dap_snprintf(l_db_path_ext, sizeof(l_db_path_ext), "%s/gdb-%s", a_filename_db, a_driver_name);

   // Check for engine
    if(!dap_strcmp(s_used_driver, "ldb"))
        l_ret = -1;
    else if(!dap_strcmp(s_used_driver, "sqlite") || !dap_strcmp(s_used_driver, "sqlite3") )
        l_ret = dap_db_driver_sqlite_init(l_db_path_ext, &s_drv_callback);
    else if(!dap_strcmp(s_used_driver, "cdb"))
        l_ret = dap_db_driver_cdb_init(l_db_path_ext, &s_drv_callback);
#ifdef DAP_CHAIN_GDB_ENGINE_MDBX
    else if(!dap_strcmp(s_used_driver, "mdbx"))
        l_ret = dap_db_driver_mdbx_init(l_db_path_ext, &s_drv_callback);
#endif
#ifdef DAP_CHAIN_GDB_ENGINE_PGSQL
    else if(!dap_strcmp(s_used_driver, "pgsql"))
        l_ret = dap_db_driver_pgsql_init(l_db_path_ext, &s_drv_callback);
#endif
    else
        log_it(L_ERROR, "Unknown global_db driver \"%s\"", a_driver_name);

    return l_ret;
}

/**
 * @brief Deinitializes a database driver.
 * @note You should call this function after using the driver.
 * @return (none)
 */
void dap_db_driver_deinit(void)
{
    log_it(L_NOTICE, "DeInit for %s ...", s_used_driver);

    if ( s_db_drvmode_async )                                               /* Let's finishing outstanding DB request ... */
    {
        for ( int i = 7; i-- && s_db_reqs_list.nr; )
        {
            log_it(L_WARNING, "Let's finished outstanding DB requests (%d) ... ",  s_db_reqs_list.nr);
            for ( int j = 3; (j = sleep(j)); );                             /* Hibernate for 3 seconds ... */
        }

        log_it(L_INFO, "Number of outstanding DB requests: %d",  s_db_reqs_list.nr);
    }

    // deinit driver
    if(s_drv_callback.deinit)
        s_drv_callback.deinit();

    s_used_driver [ 0 ] = '\0';
}

/**
 * @brief Flushes a database cahce to disk.
 * @return Returns 0, if successful; otherwise <0.
 */
int dap_db_driver_flush(void)
{
    return s_db_drvmode_async ? 0 : s_drv_callback.flush();
}

/**
 * @brief Copies objects from a_store_obj.
 * @param a_store_obj a pointer to the source objects
 * @param a_store_count a number of objects
 * @return A pointer to the copied objects.
 */
dap_store_obj_t* dap_store_obj_copy(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
dap_store_obj_t *l_store_obj, *l_store_obj_dst, *l_store_obj_src;

    if(!a_store_obj || !a_store_count)
        return NULL;

    if ( !(l_store_obj = DAP_NEW_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * a_store_count)) )
         return NULL;

    l_store_obj_dst = l_store_obj;
    l_store_obj_src = a_store_obj;

    for( int i =  a_store_count; i--; l_store_obj_dst++, l_store_obj_src++)
    {
        *l_store_obj_dst = *l_store_obj_src;

        l_store_obj_dst->group = dap_strdup(l_store_obj_src->group);
        l_store_obj_dst->key = dap_strdup(l_store_obj_src->key);
        l_store_obj_dst->value = DAP_DUP_SIZE(l_store_obj_src->value, l_store_obj_src->value_len);
        l_store_obj_dst->cb = l_store_obj_src->cb;
        l_store_obj_dst->cb_arg = l_store_obj_src->cb_arg;
    }

    return l_store_obj;
}

/**
 * @brief Deallocates memory of objects.
 * @param a_store_obj a pointer to objects
 * @param a_store_count a number of objects
 * @return (none)
 */
void dap_store_obj_free(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
    if(!a_store_obj)
        return;

    dap_store_obj_t *l_store_obj_cur = a_store_obj;

    for ( ; a_store_count--; l_store_obj_cur++ ) {
        DAP_DEL_Z(l_store_obj_cur->group);
        DAP_DEL_Z(l_store_obj_cur->key);
        DAP_DEL_Z(l_store_obj_cur->value);
    }
    DAP_DEL_Z(a_store_obj);
}

/**
 * @brief Calculates a hash of data.
 * @param data a pointer to data
 * @param data_size a size of data
 * @return Returns a hash string if successful; otherwise NULL.
 */
char* dap_chain_global_db_driver_hash(const uint8_t *data, size_t data_size)
{
    if(!data || !data_size)
        return NULL;

    dap_chain_hash_fast_t l_hash;
    memset(&l_hash, 0, sizeof(dap_chain_hash_fast_t));
    dap_hash_fast(data, data_size, &l_hash);
    size_t a_str_max = (sizeof(l_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = (size_t)dap_chain_hash_fast_to_str(&l_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL;
    }
    return a_str;
}


/**
 * @brief Applies objects to database.
 * @param a_store an pointer to the objects
 * @param a_store_count a number of objectss
 * @return Returns 0, if successful.
 */
static inline  int s_dap_chain_global_db_driver_apply_do(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
int l_ret;
dap_store_obj_t *l_store_obj_cur;

    if(!a_store_obj || !a_store_count)
        return -1;

    debug_if(s_dap_global_db_debug_more, L_DEBUG, "[%p] Process DB Request ...", a_store_obj);

    l_store_obj_cur = a_store_obj;                                          /* We have to  use a power of the address's incremental arithmetic */
    l_ret = 0;                                                              /* Preset return code to OK */

    if (a_store_count > 1 && s_drv_callback.transaction_start)
        s_drv_callback.transaction_start();

    if(s_drv_callback.apply_store_obj)
        for(int i = a_store_count; (!l_ret) && (i--); l_store_obj_cur++) {
            if ( 1 == (l_ret = s_drv_callback.apply_store_obj(l_store_obj_cur)) )
                log_it(L_INFO, "[%p] Item is missing (may be already deleted) %s/%s", a_store_obj, l_store_obj_cur->group, l_store_obj_cur->key);
            else if (l_ret < 0)
                log_it(L_ERROR, "[%p] Can't write item %s/%s (code %d)", a_store_obj, l_store_obj_cur->group, l_store_obj_cur->key, l_ret);
        }

    if(a_store_count > 1 && s_drv_callback.transaction_end)
        s_drv_callback.transaction_end();

    debug_if(s_dap_global_db_debug_more, L_DEBUG, "[%p] Finished DB Request (code %d)", a_store_obj, l_ret);
    return l_ret;
}

static bool s_dap_driver_req_exec (struct dap_proc_thread *a_dap_thd __attribute__((unused)),
                                   void *arg __attribute__((unused)) )
{
int l_ret;
dap_store_obj_t *l_store_obj_cur;
dap_worker_t        *l_dap_worker;
size_t l_store_obj_cnt;

    debug_if(s_dap_global_db_debug_more, L_DEBUG, "Entering, %d entries in the queue ...",  s_db_reqs_list.nr);

    if ( (l_ret = pthread_mutex_lock(&s_db_reqs_list_lock)) )               /* Get exclusive access to the request list */
         return log_it(L_ERROR, "Cannot lock request queue, errno=%d",l_ret), 0;

    if ( !s_db_reqs_list.nr )                                               /* Nothing to do ?! Just exit */
    {
        pthread_mutex_unlock(&s_db_reqs_list_lock);
        return  1;                                                          /* 1 - Don't call it again */
    }

    if ( (l_ret = s_dap_remqhead (&s_db_reqs_list, (void **)  &l_store_obj_cur, &l_store_obj_cnt)) )
    {
        pthread_mutex_unlock(&s_db_reqs_list_lock);
        log_it(L_ERROR, "DB Request list is in incosistence state (code %d)", l_ret);
        return  1;                                                          /* 1 - Don't call it again */
    }

    /* So at this point we are ready to do work in the DB */
    s_dap_chain_global_db_driver_apply_do(l_store_obj_cur, l_store_obj_cnt);

    pthread_mutex_unlock(&s_db_reqs_list_lock);


    /* Is there a callback  ? */
    if ( s_db_drvmode_async && l_store_obj_cur->cb )
        {
        /* Enqueue "Exec Complete" callback routine */
        l_dap_worker = dap_events_worker_get_auto ();

        if ( (l_ret = dap_proc_queue_add_callback(l_dap_worker, l_store_obj_cur->cb, (void *)l_store_obj_cur->cb_arg)) )
            log_it(L_ERROR, "[%p] Enqueue completion callback for item %s/%s (code %d)", l_store_obj_cur,
                   l_store_obj_cur->group, l_store_obj_cur->key, l_ret);
        }

    dap_store_obj_free (l_store_obj_cur, l_store_obj_cnt);                  /* Release a memory !!! */

    return  1;  /* 1 - Don't call it again */
}


/**
 * @brief Applies objects to database.
 * @param a_store an pointer to the objects
 * @param a_store_count a number of objectss
 * @return Returns 0, if successful.
 */
int dap_chain_global_db_driver_apply(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
int l_ret;
dap_store_obj_t *l_store_obj_cur;
dap_worker_t        *l_dap_worker;

    if(!a_store_obj || !a_store_count)
        return -1;

    if ( !s_db_drvmode_async )
        return s_dap_chain_global_db_driver_apply_do(a_store_obj, a_store_count);





    /* Async mode - put request into the list for deffered processing */
    l_ret = -ENOMEM;                                                    /* Preset return code to non-OK  */

    pthread_mutex_lock(&s_db_reqs_list_lock);                           /* Get exclusive access to the request list */

    if ( !(l_store_obj_cur = dap_store_obj_copy(a_store_obj, a_store_count)) )
        l_ret = - ENOMEM, log_it(L_ERROR, "[%p] No memory for DB Request for item %s/%s", a_store_obj, a_store_obj->group, a_store_obj->key);
    else if ( (l_ret = s_dap_insqtail (&s_db_reqs_list, l_store_obj_cur, a_store_count)) )
        log_it(L_ERROR, "[%p] Can't enqueue DB request for item %s/%s (code %d)", a_store_obj, a_store_obj->group, a_store_obj->key, l_ret);

    pthread_mutex_unlock(&s_db_reqs_list_lock);

    if ( !l_ret )
        {                                                                /* So finaly enqueue an execution routine */
        if ( !(l_dap_worker = dap_events_worker_get_auto ()) )
            l_ret = -EBUSY, log_it(L_ERROR, "[%p] Error process DB request for %s/%s, dap_events_worker_get_auto()->NULL", a_store_obj, l_store_obj_cur->group, l_store_obj_cur->key);
        else l_ret = dap_proc_queue_add_callback(l_dap_worker, s_dap_driver_req_exec, NULL);
        }

    debug_if(s_dap_global_db_debug_more, L_DEBUG, "[%p] DB Request has been enqueued (code %d)", l_store_obj_cur, l_ret);

    return  l_ret;
}






/**
 * @brief Adds objects to a database.
 * @param a_store_obj objects to be added
 * @param a_store_count a number of added objects
 * @return Returns 0 if sucseesful.
 */
int dap_chain_global_db_driver_add(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
dap_store_obj_t *l_store_obj_cur = a_store_obj;

    for(int i = a_store_count; i--; l_store_obj_cur++)
        l_store_obj_cur->type = DAP_DB$K_OPTYPE_ADD;

    return dap_chain_global_db_driver_apply(a_store_obj, a_store_count);
}

/**
 * @brief Deletes objects from a database.
 * @param a_store_obj objects to be deleted
 * @param a_store_count a number of deleted objects
 * @return Returns 0 if sucseesful.
 */
int dap_chain_global_db_driver_delete(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
dap_store_obj_t *l_store_obj_cur = a_store_obj;

    for(int i = a_store_count; i--; l_store_obj_cur++)
        l_store_obj_cur->type = DAP_DB$K_OPTYPE_DEL;

    return dap_chain_global_db_driver_apply(a_store_obj, a_store_count);
}

/**
 * @brief Gets a number of stored objects in a database by a_group and id.
 * @param a_group the group name string
 * @param a_id id
 * @return Returns a number of objects.
 */
size_t dap_chain_global_db_driver_count(const char *a_group, uint64_t id)
{
    size_t l_count_out = 0;
    // read the number of items
    if(s_drv_callback.read_count_store)
        l_count_out = s_drv_callback.read_count_store(a_group, id);
    return l_count_out;
}

/**
 * @brief Gets a list of group names matching the pattern.
 * Check whether the groups match the pattern a_group_mask, which is a shell wildcard pattern
 * patterns: [] {} [!] * ? https://en.wikipedia.org/wiki/Glob_(programming).
 * @param a_group_mask the group mask string
 * @return If successful, returns the list of group names, otherwise NULL.
 */
dap_list_t *dap_chain_global_db_driver_get_groups_by_mask(const char *a_group_mask)
{
    dap_list_t *l_list = NULL;
    if(s_drv_callback.get_groups_by_mask)
        l_list = s_drv_callback.get_groups_by_mask(a_group_mask);
    return l_list;
}


/**
 * @brief Reads last object in the database.
 * @param a_group the group name
 * @return If successful, a pointer to the object, otherwise NULL.
 */
dap_store_obj_t* dap_chain_global_db_driver_read_last(const char *a_group)
{
    dap_store_obj_t *l_ret = NULL;
    // read records using the selected database engine
    if(s_drv_callback.read_last_store_obj)
        l_ret = s_drv_callback.read_last_store_obj(a_group);
    return l_ret;
}

/**
 * @brief Reads several objects from a database by a_group and id.
 * @param a_group the group name string
 * @param a_id id
 * @param a_count_out[in] a number of objects to be read, if 0 - no limits
 * @param a_count_out[out] a count of objects that were read
 * @return If successful, a pointer to an objects, otherwise NULL.
 */
dap_store_obj_t* dap_chain_global_db_driver_cond_read(const char *a_group, uint64_t id, size_t *a_count_out)
{
    dap_store_obj_t *l_ret = NULL;
    // read records using the selected database engine
    if(s_drv_callback.read_cond_store_obj)
        l_ret = s_drv_callback.read_cond_store_obj(a_group, id, a_count_out);
    return l_ret;
}

/**
 * @brief Reads several objects from a database by a_group and a_key.
 * If a_key is NULL, reads whole group.
 * @param a_group a group name string
 * @param a_key  an object key string. If equal NULL, it means reading the whole group
 * @param a_count_out[in] a number of objects to be read, if 0 - no limits
 * @param a_count_out[out] a number of objects that were read
 * @return If successful, a pointer to an objects, otherwise NULL.
 */
dap_store_obj_t* dap_chain_global_db_driver_read(const char *a_group, const char *a_key, size_t *a_count_out)
{
    dap_store_obj_t *l_ret = NULL;
    // read records using the selected database engine
    if(s_drv_callback.read_store_obj)
        l_ret = s_drv_callback.read_store_obj(a_group, a_key, a_count_out);
    return l_ret;
}

/**
 * @brief Checks if an object is in a database by a_group and a_key.
 * @param a_group a group name string
 * @param a_key a object key string
 * @return Returns true if it is, false otherwise.
 */
bool dap_chain_global_db_driver_is(const char *a_group, const char *a_key)
{
    bool l_ret = NULL;
    // read records using the selected database engine
    if(s_drv_callback.is_obj)
        l_ret = s_drv_callback.is_obj(a_group, a_key);
    return l_ret;
}
