/*
 * AUTHORS:
 * Ruslan R. (The BadAss SysMan) Laishev  <ruslan.laishev@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP SDK the open source project

 DAP SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.


    DESCRIPTION: A database driver module provide an interface to MDBX API.
        https://gitflic.ru/project/erthink/libmdbx
        TG group: @libmdbx


    MODIFICATION HISTORY:

          4-MAY-2022    RRL Developing for actual version of the LibMDBX

         12-MAY-2022    RRL Finished developing of preliminary version
 */

#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <uthash.h>
#include <stdatomic.h>

#define _GNU_SOURCE

#include "dap_chain_global_db_driver_mdbx.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_common.h"

#include "mdbx.h"                                                           /* LibMDBX API */
#define LOG_TAG "dap_chain_global_db_mdbx"

extern  int s_db_drvmode_async ,                                            /* Set a kind of processing requests to DB:
                                                                            <> 0 - Async mode should be used */
        s_dap_global_db_debug_more;                                         /* Enable extensible debug output */


/** Struct for a MDBX DB context */
typedef struct __db_ctx__ {
        size_t  namelen;                                                    /* Group name length */
        char name[DAP_DB$SZ_MAXGROUPNAME + 1];                              /* Group's name */

        pthread_mutex_t dbi_mutex;                                          /* Coordinate access the MDBX's <dbi> */
        MDBX_dbi    dbi;                                                    /* MDBX's internal context id */
        MDBX_txn    *txn;                                                   /* Current MDBX's transaction */

        UT_hash_handle hh;
} dap_db_ctx_t;

static pthread_mutex_t s_db_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;          /* A mutex  for working with a DB context */



static dap_db_ctx_t *s_db_ctxs = NULL;                                      /* A hash table of <group/subDB/table> == <MDBX DB context> */
static pthread_rwlock_t s_db_ctxs_rwlock = PTHREAD_RWLOCK_INITIALIZER;      /* A read-write lock for working with a <s_db_ctxs>. */

static char s_db_path[MAX_PATH];                                            /* A root directory for the MDBX files */

/* Forward declarations of action routines */
static int              s_db_mdbx_deinit();
static int              s_db_mdbx_flush(void);
static int              s_db_mdbx_apply_store_obj (dap_store_obj_t *a_store_obj);
static dap_store_obj_t  *s_db_mdbx_read_last_store_obj(const char* a_group);
static int              s_db_mdbx_is_obj(const char *a_group, const char *a_key);
static dap_store_obj_t  *s_db_mdbx_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out);
static dap_store_obj_t  *s_db_mdbx_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out);
static size_t           s_db_mdbx_read_count_store(const char *a_group, uint64_t a_id);
static dap_list_t       *s_db_mdbx_get_groups_by_mask(const char *a_group_mask);


static MDBX_env *s_mdbx_env;                                                /* MDBX's context area */
static char s_subdir [] = "";                                               /* Name of subdir for the MDBX's database files */

static char s_db_master_tbl [] = "MDBX$MASTER";                             /* A name of master table in the MDBX
                                                                              to keep and maintains application level information */
static MDBX_dbi s_db_master_dbi;                                            /* A handle of the MDBX' DBI of the master subDB */


/*
 * Suffix structure is supposed to be added at end of MDBX record, so :
 * <value> + <suffix>
 */
struct  __record_suffix__ {
        uint64_t        mbz;                                                /* Must Be Zero ! */
        uint64_t        id;                                                 /* An uniqe-like Id of the record - internaly created and maintained */
        uint64_t        flags;                                              /* Flag of the record : see RECORD_FLAGS enums */
        dap_time_t      ts;                                                 /* Timestamp of the record */
};

#if     __SYS$DEBUG__
/*
 *  DESCRIPTION: Dump all records from the table . Is supposed to be used at debug time.
 *
 *  INPUTS:
 *      a_db_ctx:   DB context
 *
 *  OUTPUTS:
 *      NONE:
 *
 *  RETURNS:
 *      NONE
 */
static void s_db_dump (dap_db_ctx_t *a_db_ctx)
{
int l_rc;
MDBX_val    l_key_iov, l_data_iov;
MDBX_cursor *l_cursor;
char    l_buf[1024] = {0};

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &a_db_ctx->txn)) )
        log_it(L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc));
    else if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(a_db_ctx->txn, a_db_ctx->dbi, &l_cursor)) )
        log_it(L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
    else {
        while ( !(l_rc = mdbx_cursor_get (l_cursor, &l_key_iov, &l_data_iov, MDBX_NEXT )) )
            {
            l_rc = dap_bin2hex (l_buf, l_data_iov.iov_base, min(l_data_iov.iov_len, 72) );

            debug_if(s_dap_global_db_debug_more, L_DEBUG, "[0:%zu]: '%.*s' = [0:%zu]: '%.*s'",
                    l_key_iov.iov_len, (int) l_key_iov.iov_len, l_key_iov.iov_base,
                    l_data_iov.iov_len, l_rc, l_buf);
            }
    }

    if (l_cursor)
        mdbx_cursor_close(l_cursor);

    if (a_db_ctx->txn)
        mdbx_txn_abort(a_db_ctx->txn);
}
#endif     /* __SYS$DEBUG__ */


static dap_db_ctx_t *s_cre_db_ctx_for_group(const char *a_group, int a_flags)
{
int l_rc;
dap_db_ctx_t *l_db_ctx, *l_db_ctx2;
uint64_t l_seq;
MDBX_val    l_key_iov, l_data_iov;

    debug_if(s_dap_global_db_debug_more, L_DEBUG, "Init group/table '%s', flags: %#x ...", a_group, a_flags);


    assert( !pthread_rwlock_rdlock(&s_db_ctxs_rwlock) );                    /* Get RD lock for lookup only */
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx);                            /* Is there exist context for the group ? */
    assert( !pthread_rwlock_unlock(&s_db_ctxs_rwlock) );

    if ( l_db_ctx )                                                         /* Found! Good job - return DB context */
        return  log_it(L_INFO, "Found DB context: %p for group: '%s'", l_db_ctx, a_group), l_db_ctx;

//    if ( !(a_flags & MDBX_CREATE) )                                         /* Not found and we don't need to create it ? */
//        return  NULL;

    /* So , at this point we are going to create (if not exist)  'table' for new group */

    if ( (l_rc = strlen(a_group)) > DAP_DB$SZ_MAXGROUPNAME )                /* Check length of the group name */
        return  log_it(L_ERROR, "Group name '%s' is too long (%d>%d)", a_group, l_rc, DAP_DB$SZ_MAXGROUPNAME), NULL;

    if ( !(l_db_ctx = DAP_NEW_Z(dap_db_ctx_t)) )                            /* Allocate zeroed memory for new DB context */
        return  log_it(L_ERROR, "Cannot allocate DB context for '%s', errno=%d", a_group, errno), NULL;

    memcpy(l_db_ctx->name,  a_group, l_db_ctx->namelen = l_rc);             /* Store group name in the DB context */
    assert ( !pthread_mutex_init(&l_db_ctx->dbi_mutex, NULL));

    /*
    ** Start transaction, create table, commit.
    */
    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
        return  log_it(L_CRITICAL, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;

    if  ( MDBX_SUCCESS != (l_rc = mdbx_dbi_open(l_db_ctx->txn, a_group, a_flags, &l_db_ctx->dbi)) )
        return  log_it(L_CRITICAL, "mdbx_dbi_open: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;

    /* MDBX sequence is started from zero, zero is not so good for our case,
     * so we just increment a current (may be is not zero) sequence for <dbi>
     */
    mdbx_dbi_sequence (l_db_ctx->txn, l_db_ctx->dbi, &l_seq, 1);

    /*
     * Save new subDB name into the master table
     */
    l_data_iov.iov_base =  l_key_iov.iov_base = l_db_ctx->name;
    l_data_iov.iov_len = l_key_iov.iov_len = l_db_ctx->namelen;
    l_data_iov.iov_len += 1;    /* Count '\0' */

    if ( MDBX_SUCCESS != (l_rc = mdbx_put(l_db_ctx->txn, s_db_master_dbi, &l_key_iov, &l_data_iov, MDBX_NOOVERWRITE ))
         && (l_rc != MDBX_KEYEXIST) )
    {
        log_it (L_ERROR, "mdbx_put: (%d) %s", l_rc, mdbx_strerror(l_rc));

        if ( MDBX_SUCCESS != (l_rc = mdbx_txn_abort(l_db_ctx->txn)) )
            return  log_it(L_CRITICAL, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;
    }

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
        return  log_it(L_CRITICAL, "mdbx_txn_commit: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;

    /*
    ** Add new DB Context for the group into the hash for quick access
    */
    assert( !pthread_rwlock_wrlock(&s_db_ctxs_rwlock) );                    /* Get WR lock for the hash-table */

    l_db_ctx2 = NULL;
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx2);                           /* Check for existence of group again!!! */

    if ( !l_db_ctx2)                                                        /* Still not exist - fine, add new record */
        HASH_ADD_KEYPTR(hh, s_db_ctxs, l_db_ctx->name, l_db_ctx->namelen, l_db_ctx);

    assert( !pthread_rwlock_unlock(&s_db_ctxs_rwlock) );

    if ( l_db_ctx2 )                                                        /* Release unnecessary new context */
        DAP_DEL_Z(l_db_ctx);

    return l_db_ctx2 ? l_db_ctx2 : l_db_ctx;
}





static  int s_db_mdbx_deinit(void)
{
dap_db_ctx_t *l_db_ctx = NULL, *l_tmp;

    assert ( !pthread_rwlock_wrlock(&s_db_ctxs_rwlock) );                   /* Prelock for WR */

    HASH_ITER(hh, s_db_ctxs, l_db_ctx, l_tmp)                               /* run over the hash table of the DB contexts */
    {
        HASH_DEL(s_db_ctxs, l_db_ctx);                                      /* Delete DB context from the hash-table */

        assert( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );
        if (l_db_ctx->txn)                                                  /* Commit, close table */
            mdbx_txn_commit(l_db_ctx->txn);

        if (l_db_ctx->dbi)
            mdbx_dbi_close(s_mdbx_env, l_db_ctx->dbi);
        assert( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

        DAP_DELETE(l_db_ctx);                                               /* Release memory of DB context area */
    }

    if (s_mdbx_env)
        mdbx_env_close(s_mdbx_env);                                         /* Finaly close MDBX DB */

    assert ( !pthread_rwlock_unlock(&s_db_ctxs_rwlock) );

    return 0;
}


int     dap_db_driver_mdbx_init(const char *a_mdbx_path, dap_db_driver_callbacks_t *a_drv_callback)
{
int l_rc;
MDBX_txn    *l_txn;
MDBX_cursor *l_cursor;
MDBX_val    l_key_iov, l_data_iov;
dap_slist_t l_slist = {0};
char        *l_cp;

    snprintf(s_db_path, sizeof(s_db_path), "%s/%s", a_mdbx_path, s_subdir );/* Make a path to MDBX root */
    dap_mkdir_with_parents(s_db_path);                                      /* Create directory for the MDBX storage */

    log_it(L_NOTICE, "Directory '%s' will be used as an location for MDBX database files", s_db_path);
    s_mdbx_env = NULL;
    if ( MDBX_SUCCESS != (l_rc = mdbx_env_create(&s_mdbx_env)) )
        return  log_it(L_CRITICAL, "mdbx_env_create: (%d) %s", l_rc, mdbx_strerror(l_rc)), -ENOENT;

#if 0
    if ( s_dap_global_db_debug_more )
        mdbx_setup_debug	(	MDBX_LOG_VERBOSE, 0, 0);
#endif


    log_it(L_NOTICE, "Set maximum number of local groups: %d", DAP_DB$K_MAXGROUPS);
    assert ( !mdbx_env_set_maxdbs (s_mdbx_env, DAP_DB$K_MAXGROUPS) );       /* Set maximum number of the file-tables (MDBX subDB)
                                                                              according to number of supported groups */


                                                                            /* We set "unlim" for all MDBX characteristics at the moment */


    if ( MDBX_SUCCESS != (l_rc = mdbx_env_set_geometry(s_mdbx_env, -1, -1, DAP_DB$SZ_MAXDB, -1, -1, -1)) )
        return  log_it (L_CRITICAL, "mdbx_env_set_geometry (%s): (%d) %s", s_db_path, l_rc, mdbx_strerror(l_rc)),  -EINVAL;

    if ( MDBX_SUCCESS != (l_rc = mdbx_env_open(s_mdbx_env, s_db_path, MDBX_CREATE |  MDBX_COALESCE | MDBX_LIFORECLAIM, 0664)) )
        return  log_it (L_CRITICAL, "mdbx_env_open (%s): (%d) %s", s_db_path, l_rc, mdbx_strerror(l_rc)),  -EINVAL;

    /*
     * Since MDBX don't maintain a list of subDB with public API, we will use a "MASTER Table",
     * be advised that this MASTER teble is not maintained accurately!!!
     *
     * So, Create (If)/Open a master DB (table) to keep  list of subDBs (group/table/subDB name)
    */
    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_txn)) )
        return  log_it(L_CRITICAL, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), -EIO;

    if ( MDBX_SUCCESS != (l_rc = mdbx_dbi_open(l_txn, s_db_master_tbl, MDBX_CREATE, &s_db_master_dbi)) )
        return  log_it(L_CRITICAL, "mdbx_dbi_open: (%d) %s", l_rc, mdbx_strerror(l_rc)), -EIO;

    assert ( MDBX_SUCCESS == (l_rc = mdbx_txn_commit (l_txn)) );

    /*
     * Run over records in the  MASTER table to get subDB names
     */
    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_txn)) )
        log_it(L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc));
    else if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(l_txn, s_db_master_dbi, &l_cursor)) )
        log_it(L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
    else{
        debug_if(s_dap_global_db_debug_more, L_DEBUG, "--- List of stored groups ---");

        for ( int i = 0;  !(l_rc = mdbx_cursor_get (l_cursor, &l_key_iov, &l_data_iov, MDBX_NEXT )); i++ )
            {
            debug_if(s_dap_global_db_debug_more, L_DEBUG, "MDBX SubDB #%03d [0:%zu]: '%.*s' = [0:%zu]: '%.*s'", i,
                    l_key_iov.iov_len, (int) l_key_iov.iov_len, (char *)l_key_iov.iov_base,
                    l_data_iov.iov_len, (int) l_data_iov.iov_len, (char *)l_data_iov.iov_base);

            /* Form a simple list of the group/table name to be used after */
            l_cp = dap_strdup(l_data_iov.iov_base);                         /* We expect an ASCIZ string as the table name */
            l_data_iov.iov_len = strlen(l_cp);
            s_dap_insqtail(&l_slist, l_cp, l_data_iov.iov_len);
            }
        debug_if(s_dap_global_db_debug_more, L_DEBUG, "--- End-Of-List  ---");
        }

    assert ( MDBX_SUCCESS == mdbx_txn_commit (l_txn) );


    /* Run over the list and create/open group/tables and DB context ... */
    while ( !s_dap_remqhead (&l_slist, &l_data_iov.iov_base, &l_data_iov.iov_len) )
    {
        s_cre_db_ctx_for_group(l_data_iov.iov_base, MDBX_CREATE);
        DAP_DELETE(l_data_iov.iov_base);
    }

    /*
    ** Fill the Driver Interface Table
    */
    a_drv_callback->apply_store_obj     = s_db_mdbx_apply_store_obj;
    a_drv_callback->read_last_store_obj = s_db_mdbx_read_last_store_obj;

    a_drv_callback->read_store_obj      = s_db_mdbx_read_store_obj;
    a_drv_callback->read_cond_store_obj = s_db_mdbx_read_cond_store_obj;
    a_drv_callback->read_count_store    = s_db_mdbx_read_count_store;
    a_drv_callback->get_groups_by_mask  = s_db_mdbx_get_groups_by_mask;
    a_drv_callback->is_obj              = (dap_db_driver_is_obj_callback_t) s_db_mdbx_is_obj;
    a_drv_callback->deinit              = s_db_mdbx_deinit;
    a_drv_callback->flush               = s_db_mdbx_flush;

    /*
     * MDBX support transactions but under the current circuimstances we will not get
     * advantages of using DB Driver level BEGIN/END transactions
     */
    a_drv_callback->transaction_start   = NULL;
    a_drv_callback->transaction_end     = NULL;


    return MDBX_SUCCESS;
}


/**
 * @brief Gets CDB by a_group.
 * @param a_group a group name
 * @return if CDB is found, a pointer to CDB, otherwise NULL.
 */
static  dap_db_ctx_t  *s_get_db_ctx_for_group(const char *a_group)
{
dap_db_ctx_t *l_db_ctx = NULL;

    assert ( !pthread_rwlock_rdlock(&s_db_ctxs_rwlock) );
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx);
    assert ( !pthread_rwlock_unlock(&s_db_ctxs_rwlock) );

    if ( !l_db_ctx )
        debug_if(s_dap_global_db_debug_more, L_WARNING, "No DB context for the group '%s'", a_group);

    return l_db_ctx;
}

/**
 * @brief Flushing CDB to the disk.
 * @return 0
 */
static  int s_db_mdbx_flush(void)
{
    return  log_it(L_DEBUG, "Flushing resident part of the MDBX to disk"), 0;
}

/**
 * @brief Read last store item from CDB.
 * @param a_group a group name
 * @return If successful, a pointer to item, otherwise NULL.
 */
dap_store_obj_t *s_db_mdbx_read_last_store_obj(const char* a_group)
{
int l_rc;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data, l_last_data, l_last_key;
MDBX_cursor *l_cursor = NULL;
struct  __record_suffix__   *l_suff;
uint64_t    l_id;
dap_store_obj_t *l_obj;

    if (!a_group)                                                           /* Sanity check */
        return NULL;

    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_group)) )                    /* Get DB Context for group/table */
        return NULL;

    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;
    }

    do {
        l_cursor = NULL;
        l_id  = 0;
        l_last_key = l_last_data = (MDBX_val) {0, 0};

        if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(l_db_ctx->txn, l_db_ctx->dbi, &l_cursor)) ) {
          log_it (L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
          break;
        }

        /* Iterate cursor to retrieve records from DB - select a <key> and <data> pair
        ** with maximal <id>
        */
        while ( MDBX_SUCCESS == (l_rc = mdbx_cursor_get(l_cursor, &l_key, &l_data, MDBX_NEXT)) )
        {
            l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_data.iov_len - sizeof(struct __record_suffix__));
            if ( l_id < l_suff->id )
            {
                l_id = l_suff->id;
                l_last_key = l_key;
                l_last_data = l_data;
            }
        }

    } while (0);

    if (l_cursor)
        mdbx_cursor_close(l_cursor);
    if (l_db_ctx->txn)
        mdbx_txn_commit(l_db_ctx->txn);


    if ( !(l_last_key.iov_len || l_data.iov_len) )                          /* Not found anything  - return NULL */
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  NULL;
    }


    /* Found ! Allocate memory for  <store object>  and <value> */
    if ( (l_obj = DAP_CALLOC(1, sizeof( dap_store_obj_t ))) )
    {
        if ( (l_obj->value = DAP_CALLOC(1, (l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
            {
            /* Fill the <store obj> by data from the retrieved record */
            l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
            memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

            l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
            l_obj->id = l_suff->id;
            l_obj->timestamp = l_suff->ts;
            l_obj->flags = l_suff->flags;
            assert ( (l_obj->group = dap_strdup(a_group)) );
        }
        else {
            DAP_DEL_Z(l_obj);
            log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
        }
    }
    else  log_it (L_ERROR, "Cannot allocate a memory for store object, errno=%d", errno);

    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    return  l_obj;
}

/**
 * @brief s_db_mdbx_is_obj  Check for existence of the record with a given group/key combination
 * @param a_group   a group/table name
 * @param a_key     a key to be check
 * @return  0 - Record-Not-Found
 *          1 - Record is found
 */
int     s_db_mdbx_is_obj(const char *a_group, const char *a_key)
{
int l_rc, l_rc2;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data;

    if (!a_group)                                                           /* Sanity check */
        return 0;

    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_group)) )                    /* Get DB Context for group/table */
        return 0;

    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), 0;
    }

    l_key.iov_base = (void *) a_key;                                        /* Fill IOV for MDBX key */
    l_key.iov_len =  strlen(a_key);

    l_rc = mdbx_get(l_db_ctx->txn, l_db_ctx->dbi, &l_key, &l_data);

    if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_commit(l_db_ctx->txn)) )
        log_it (L_ERROR, "mdbx_txn_commit: (%d) %s", l_rc2, mdbx_strerror(l_rc2));

    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    return ( l_rc == MDBX_SUCCESS );    /*0 - RNF, 1 - SUCCESS */
}


/**
 * @brief Gets items from CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @param a_count_out[in] a count of items
 * @param a_count[out] a count of items were got
 * @return If successful, pointer to items, otherwise NULL.
 */
static dap_store_obj_t  *s_db_mdbx_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out)
{
int l_rc;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data;
MDBX_cursor *l_cursor;
struct  __record_suffix__   *l_suff;
dap_store_obj_t *l_obj;

    if (!a_group)                                                           /* Sanity check */
        return NULL;

    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_group)) )                    /* Get DB Context for group/table */
        return NULL;

    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;
    }


    l_cursor = NULL;
    *a_count_out = 0;

    do {
        if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(l_db_ctx->txn, l_db_ctx->dbi, &l_cursor)) ) {
          log_it (L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
          break;
        }

        /* Iterate cursor to retrieve records from DB - select a <key> and <data> pair
        ** with maximal <id>
        */
        l_key.iov_base = "";
        l_key.iov_len =  0;

        while ( MDBX_SUCCESS == (l_rc = mdbx_cursor_get(l_cursor, &l_key, &l_data, MDBX_NEXT)) )
        {
            l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_data.iov_len - sizeof(struct __record_suffix__));
            if ( a_id < l_suff->id ) {
                *a_count_out = 1;
                break;
            }
        }

    } while (0);

    if (l_cursor)
        mdbx_cursor_close(l_cursor);
    if (l_db_ctx->txn)
        mdbx_txn_commit(l_db_ctx->txn);


    if ( l_rc != MDBX_SUCCESS )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  NULL;
    }

    /* Found ! Allocate memory to <store object> < and <value> */
    if ( (l_obj = DAP_CALLOC(1, sizeof( dap_store_obj_t ))) )
    {
        if ( (l_obj->value = DAP_CALLOC(1, (l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
            {
            /* Fill the <store obj> by data from the retreived record */
            l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
            memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

            l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
            l_obj->id = l_suff->id;
            l_obj->timestamp = l_suff->ts;
            l_obj->flags = l_suff->flags;
            assert ( (l_obj->group = dap_strdup(a_group)) );
        }
        else {
            DAP_DEL_Z(l_obj);
            log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
        }
    }
    else log_it (L_ERROR, "Cannot allocate a memory for store object, errno=%d", errno);

    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    return  l_obj;
}


/**
 * @brief Reads count of items in CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @return If successful, count of store items; otherwise 0.
 */
size_t  s_db_mdbx_read_count_store(const char *a_group, uint64_t a_id)
{
int l_rc, l_count_out;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data;
MDBX_cursor *l_cursor;
struct  __record_suffix__   *l_suff;

    if (!a_group)                                                           /* Sanity check */
        return 0;

    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_group)) )                      /* Get DB Context for group/table */
        return 0;

    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), 0;
    }

    l_cursor = NULL;
    l_count_out = 0;

    do {

        if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(l_db_ctx->txn, l_db_ctx->dbi, &l_cursor)) ) {
          log_it (L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
          break;
        }

                                                                            /* Iterate cursor to retrieve records from DB */
        while ( MDBX_SUCCESS == (l_rc = mdbx_cursor_get(l_cursor, &l_key, &l_data, MDBX_NEXT)) )
        {
            l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_data.iov_len - sizeof(struct __record_suffix__));
            l_count_out += (a_id == l_suff->id );
        }

    } while (0);

    if (l_cursor)
        mdbx_cursor_close(l_cursor);
    if (l_db_ctx->txn)
        mdbx_txn_commit(l_db_ctx->txn);

    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    if ( l_count_out > 1 )                                                  /* We don't expect to retrieve more then 1 record
                                                                              because we use unique generated sequence for the  <id> field for the
                                                                              record. But this fucking shit is took place in the CDB so ...
                                                                              */
        log_it(L_WARNING, "A count of records with id: %zu - more then 1 (%d) !!!", a_id, l_count_out);

    return  l_count_out;
}


static dap_list_t  *s_db_mdbx_get_groups_by_mask(const char *a_group_mask)
{
dap_list_t *l_ret_list;
dap_db_ctx_t *l_db_ctx, *l_db_ctx2;

    if(!a_group_mask)
        return NULL;

    l_ret_list = NULL;

    assert ( !pthread_rwlock_rdlock(&s_db_ctxs_rwlock) );

    HASH_ITER(hh, s_db_ctxs, l_db_ctx, l_db_ctx2) {
        if (!dap_fnmatch(a_group_mask, l_db_ctx->name, 0) )                 /* Name match a pattern/mask ? */
            l_ret_list = dap_list_prepend(l_ret_list, dap_strdup(l_db_ctx->name)); /* Add group name to output list */
    }

    assert ( !pthread_rwlock_unlock(&s_db_ctxs_rwlock) );

    return l_ret_list;
}



static  int s_db_mdbx_apply_store_obj (dap_store_obj_t *a_store_obj)
{
int     l_rc = 0, l_rc2;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data;
char    *l_val;
struct  __record_suffix__   *l_suff;

    if ( !a_store_obj || !a_store_obj->group)                               /* Sanity checks ... */
        return -EINVAL;



    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_store_obj->group)) ) {        /* Get a DB context for the group */
        log_it(L_WARNING, "No DB context for the group '%s', create it ...", a_store_obj->group);
                                                                            /* Group is not found ? Try to create table for new group */
        if ( !(l_db_ctx = s_cre_db_ctx_for_group(a_store_obj->group, MDBX_CREATE)) )
            return  log_it(L_WARNING, "Cannot create DB context for the group '%s'", a_store_obj->group), -EIO;

        log_it(L_NOTICE, "DB context for the group '%s' has been created", a_store_obj->group);

        if ( a_store_obj->type == DAP_DB$K_OPTYPE_DEL )                     /* Nothing to do anymore */
            return  0;
    }


    /* At this point we have got the DB Context for the table/group
     * so we are can performs a main work
     */

    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );


    if (a_store_obj->type == DAP_DB$K_OPTYPE_ADD ) {
        if( !a_store_obj->key )
        {
            assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
            return -ENOENT;
        }

        l_key.iov_base = (void *) a_store_obj->key;                         /* Fill IOV for MDBX key */
        l_key.iov_len =  a_store_obj->key_len ? a_store_obj->key_len : strnlen(a_store_obj->key, DAP_DB$SZ_MAXKEY);

        /*
         * Now we are ready  to form a record in next format:
         * <value> + <suffix>
         */
        l_rc = a_store_obj->value_len + sizeof(struct  __record_suffix__); /* Compute a length of the area to keep value+suffix */

        if ( !(l_val = DAP_NEW_Z_SIZE(char, l_rc)) )
        {
            assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
            return  log_it(L_ERROR, "Cannot allocate memory for new records, %d octets, errno=%d", l_rc, errno), -errno;
        }

        l_data.iov_base = l_val;                                            /* Fill IOV for MDBX data */
        l_data.iov_len = l_rc;

        /*
         * Fill suffix's fields
        */
        l_suff = (struct __record_suffix__ *) (l_val + a_store_obj->value_len);
        l_suff->flags = a_store_obj->flags;
        l_suff->ts = a_store_obj->timestamp;

        memcpy(l_val, a_store_obj->value, a_store_obj->value_len);          /* Put <value> into the record */

        /* So, finaly: BEGIN transaction, do INSERT, COMMIT or ABORT ... */
        if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
        {
            assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
            return  DAP_FREE(l_val), log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), -EIO;
        }


                                                                            /* Generate <sequence number> for new record */
        if ( MDBX_SUCCESS != mdbx_dbi_sequence	(l_db_ctx->txn, l_db_ctx->dbi, &l_suff->id, 1) )
        {
            log_it (L_CRITICAL, "mdbx_dbi_sequence: (%d) %s", l_rc, mdbx_strerror(l_rc));

            if ( MDBX_SUCCESS != (l_rc = mdbx_txn_abort(l_db_ctx->txn)) )
                log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc));

            assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

            return  DAP_FREE(l_val), -EIO;
        }



        if ( MDBX_SUCCESS != (l_rc = mdbx_put(l_db_ctx->txn, l_db_ctx->dbi, &l_key, &l_data, 0)) )
        {
            log_it (L_ERROR, "mdbx_put: (%d) %s", l_rc, mdbx_strerror(l_rc));

            if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_abort(l_db_ctx->txn)) )
                log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc2, mdbx_strerror(l_rc2));
        }
        else if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
            log_it (L_ERROR, "mdbx_txn_commit: (%d) %s", l_rc, mdbx_strerror(l_rc));

        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

        return DAP_FREE(l_val), (( l_rc == MDBX_SUCCESS ) ? 0 : -EIO);
    } /* DAP_DB$K_OPTYPE_ADD */



    if (a_store_obj->type == DAP_DB$K_OPTYPE_DEL)  {
        if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
        {
            assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

            return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), -ENOENT;
        }

        l_rc2 = 0;

        if ( a_store_obj->key ) {                                           /* Delete record */
                l_key.iov_base = (void *) a_store_obj->key;
                l_key.iov_len =  a_store_obj->key_len ? a_store_obj->key_len : strnlen(a_store_obj->key, DAP_DB$SZ_MAXKEY);

                if ( MDBX_SUCCESS != (l_rc = mdbx_del(l_db_ctx->txn, l_db_ctx->dbi, &l_key, NULL))
                     && ( l_rc != MDBX_NOTFOUND) )
                    l_rc2 = -EIO, log_it (L_ERROR, "mdbx_del: (%d) %s", l_rc, mdbx_strerror(l_rc));
            }
        else {                                                              /* Truncate only  table */
                if ( MDBX_SUCCESS != (l_rc = mdbx_drop(l_db_ctx->txn, l_db_ctx->dbi, 0))
                     && ( l_rc != MDBX_NOTFOUND) )
                    l_rc2 = -EIO, log_it (L_ERROR, "mdbx_drop: (%d) %s", l_rc, mdbx_strerror(l_rc));
            }


        l_rc = (l_rc == MDBX_NOTFOUND) ? MDBX_SUCCESS : l_rc;               /* Not found ?! It's Okay !!! */



        if ( l_rc != MDBX_SUCCESS ) {                                       /* Check result of mdbx_drop/del */
            if ( MDBX_SUCCESS != (l_rc = mdbx_txn_abort(l_db_ctx->txn)) )
                l_rc2 = -EIO, log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc));
        }
        else if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
            l_rc2 = -EIO, log_it (L_ERROR, "mdbx_txn_commit: (%d) %s", l_rc, mdbx_strerror(l_rc));

        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

        return ( l_rc2 == MDBX_SUCCESS ) ? 0 : -EIO;
    } /* DAP_DB$K_OPTYPE_DEL */


    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    log_it (L_ERROR, "Unhandle/unknown DB opcode (%d/%#x)", a_store_obj->type, a_store_obj->type);

    return  -EIO;
}







/**
 * @brief Gets items from CDB by a_group and a_key. If a_key=NULL then gets a_count_out items.
 * @param a_group the group name
 * @param a_key the key or NULL
 * @param a_count_out IN. Count of read items. OUT Count of items was read
 * @return If successful, pointer to items; otherwise NULL.
 */
static dap_store_obj_t *s_db_mdbx_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out)
{
int l_rc, l_rc2, l_count_out;
dap_db_ctx_t *l_db_ctx;
dap_store_obj_t *l_obj, *l_obj_arr;
MDBX_val    l_key, l_data;
MDBX_cursor *l_cursor;
MDBX_stat   l_stat;
struct  __record_suffix__   *l_suff;


    if (!a_group)                                                           /* Sanity check */
        return NULL;

    if ( !(l_db_ctx = s_get_db_ctx_for_group(a_group)) )                    /* Get DB Context for group/table */
        return NULL;


    assert ( !pthread_mutex_lock(&l_db_ctx->dbi_mutex) );

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
    {
        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;
    }


    if ( a_count_out )
        *a_count_out = 0;

    /*
     *  Perfroms a find/get a record with the given key
     */
    if ( a_key )
    {
        l_key.iov_base = (void *) a_key;                                    /* Fill IOV for MDBX key */
        l_key.iov_len =  strlen(a_key);
        l_obj = NULL;

        if ( MDBX_SUCCESS == (l_rc = mdbx_get(l_db_ctx->txn, l_db_ctx->dbi, &l_key, &l_data)) )
        {
            /* Found ! Allocate memory to <store object> < and <value> */
            if ( (l_obj = DAP_CALLOC(1, sizeof( dap_store_obj_t ))) )
            {
                if ( (l_obj->value = DAP_CALLOC(1, (l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
                    {
                    /* Fill the <store obj> by data from the retreived record */
                    l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
                    memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

                    l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
                    l_obj->id = l_suff->id;
                    l_obj->timestamp = l_suff->ts;
                    l_obj->flags = l_suff->flags;
                    assert ( (l_obj->group = dap_strdup(a_group)) );

                    if ( a_count_out )
                        *a_count_out = 1;
                }
                else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
            }
            else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object, errno=%d", errno);
        } else if ( l_rc != MDBX_NOTFOUND)
            log_it (L_ERROR, "mdbx_get: (%d) %s", l_rc, mdbx_strerror(l_rc));

        if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_commit(l_db_ctx->txn)) )
            log_it (L_ERROR, "mdbx_txn_commit: (%d) %s", l_rc2, mdbx_strerror(l_rc2));

        if ( (l_rc != MDBX_SUCCESS) && l_obj ) {
            DAP_FREE(l_obj->value);
            DAP_DEL_Z(l_obj);
        }


        assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

        return ( l_rc == MDBX_SUCCESS ) ? l_obj : NULL;
    }





    /*
    ** If a_key is NULL - retrieve a requested number of records from the table
    */
    do  {
        l_count_out = a_count_out? *a_count_out : DAP_DB$K_MAXOBJS;             /* Limit a number of objects to be returned */
        l_cursor = NULL;
        l_obj = NULL;

        /*
         * Retrieve statistic for group/table, we need to compute a number of records can be retreived
         */
        l_rc2 = 0;
        if ( MDBX_SUCCESS != (l_rc = mdbx_dbi_stat	(l_db_ctx->txn, l_db_ctx->dbi, &l_stat, sizeof(MDBX_stat))) ) {
            log_it (L_ERROR, "mdbx_dbi_stat: (%d) %s", l_rc2, mdbx_strerror(l_rc2));
            break;
        }
        else if ( !l_stat.ms_entries )                                      /* Nothing to retrieve , table contains no record */
            break;

        if ( !(l_count_out = min(l_stat.ms_entries, l_count_out)) ) {
            debug_if(s_dap_global_db_debug_more, L_WARNING, "No object (-s) to be retrieved from the group '%s'", a_group);
            break;
        }

        /*
         * Allocate memory for array of returned objects
        */
        l_rc2 = l_count_out * sizeof(dap_store_obj_t);
        if ( !(l_obj_arr = (dap_store_obj_t *) DAP_NEW_Z_SIZE(char, l_rc2)) ) {
            log_it(L_ERROR, "Cannot allocate %zu octets for %d store objects", l_count_out * sizeof(dap_store_obj_t), l_count_out);
            break;
        }

                                                                            /* Initialize MDBX cursor context area */
        if ( MDBX_SUCCESS != (l_rc = mdbx_cursor_open(l_db_ctx->txn, l_db_ctx->dbi, &l_cursor)) ) {
          log_it (L_ERROR, "mdbx_cursor_open: (%d) %s", l_rc, mdbx_strerror(l_rc));
          break;
        }

                                                                            /* Iterate cursor to retieve records from DB */
        l_obj = l_obj_arr;
        for (int i = l_count_out; i && (l_rc = mdbx_cursor_get(l_cursor, &l_key, &l_data, MDBX_NEXT)); i--, l_obj++)
        {
            if ( (l_obj->value = DAP_CALLOC(1, (l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
                {
                /* Fill the <store obj> by data from the retreived record */
                l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
                memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

                l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
                l_obj->id = l_suff->id;
                l_obj->timestamp = l_suff->ts;
                l_obj->flags = l_suff->flags;
                assert ( (l_obj->group = dap_strdup(a_group)) );

                if ( a_count_out )
                    *a_count_out += 1;
                }
            else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
        }

        if ( (MDBX_SUCCESS != l_rc) && (l_rc != MDBX_NOTFOUND) )
        {
          log_it (L_ERROR, "mdbx_cursor_get: (%d) %s", l_rc, mdbx_strerror(l_rc)), l_rc = MDBX_SUCCESS;
          break;
        }
    } while (0);

    if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_commit(l_db_ctx->txn)) )
        log_it (L_ERROR, "mdbx_txn_commit: (%d) %s", l_rc2, mdbx_strerror(l_rc2));

    if (l_cursor)
        mdbx_cursor_close(l_cursor);
    if (l_db_ctx->txn)
        mdbx_txn_commit(l_db_ctx->txn);


    assert ( !pthread_mutex_unlock(&l_db_ctx->dbi_mutex) );

    return l_obj_arr;
}
