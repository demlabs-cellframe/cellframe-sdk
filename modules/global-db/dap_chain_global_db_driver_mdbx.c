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

    DESCRIPTION:

    DESIGN ISSUE:

    MODIFICATION HISTORY:
         4-MAY-2022 RRL Developing for actual version of the LibMDBX
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

#define DAP_CHAIN_GDB_ENGINE_MDBX   1
//#ifdef DAP_CHAIN_GDB_ENGINE_MDBX

#include "mdbx.h"                                                           /* LibMDBX API */
#define LOG_TAG "dap_chain_global_db_mdbx"

/** Struct for a MDBX instanse */
typedef struct __db_ctx__ {
        atomic_ullong   id;                                                 /* Just a counter of  */
        size_t  namelen;                                                    /* Group name length */
        char name[DAP_DB$SZ_MAXGROUPNAME + 1];                              /* Group's name */
        MDBX_dbi    dbi;                                                    /* MDBX's internal context id */
        MDBX_txn    *txn;                                                   /* Current MDBX's transaction */
        UT_hash_handle hh;
} dap_db_ctx_t;


/** Struct for a item */
typedef struct _obj_arg {
    pdap_store_obj_t o;
    uint64_t q;
    uint64_t n;
    uint64_t id;
} obj_arg;


static dap_db_ctx_t *s_db_ctxs = NULL;                                      /* A pointer to a CDB instance. */
static pthread_mutex_t s_db_mutex = PTHREAD_MUTEX_INITIALIZER;              /* A mutex for working with a DB instanse. */
static pthread_rwlock_t s_db_rwlock = PTHREAD_RWLOCK_INITIALIZER;           /* A read-write lock for working with a DB instanse. */

static char s_db_path[MAX_PATH];                                            /* A root directory for the MDBX files */

/* Forward declarations of routines */
static int              s_deinit();
static int              s_flush(void);
static int              s_apply_store_obj (dap_store_obj_t *a_store_obj);
static dap_store_obj_t *s_read_last_store_obj(const char* a_group);
static int              s_is_obj(const char *a_group, const char *a_key);
static dap_store_obj_t *s_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out);
static dap_store_obj_t  *s_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out);
static size_t           s_read_count_store(const char *a_group, uint64_t a_id);
static dap_list_t       *s_get_groups_by_mask(const char *a_group_mask);


static MDBX_env *s_mdbx_env;                                                /* MDBX's context area */
static char s_subdir [] = "mdbx-db";                                        /* Name of subdir for the MDBX's database files */







static dap_db_ctx_t *s_db_ctx_init_by_group(const char *a_group, int a_flags)
{
int l_rc;
dap_db_ctx_t *l_db_ctx, *l_db_ctx2;

    assert( !pthread_rwlock_rdlock(&s_db_rwlock) );                         /* Get RD lock for lookup only */
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx);                            /* Is there exist context for the group ? */
    assert( !pthread_rwlock_unlock(&s_db_rwlock) );

    if ( l_db_ctx )                                                         /* Found! Good job - return DB context */
        return  log_it(L_INFO, "Found DB context: %p for group: '%s'", l_db_ctx, a_group), l_db_ctx;

    if ( !(a_flags & MDBX_CREATE) )                                          /* Not found and we don't need to create it ? */
        return  NULL;

    /* So , at this point we are going to create 'table' for new group */

    if ( (l_rc = strlen(a_group)) > DAP_DB$SZ_MAXGROUPNAME )                /* Check length of the group name */
        return  log_it(L_ERROR, "Group name '%s' is too long (%d>%d)", a_group, l_rc, DAP_DB$SZ_MAXGROUPNAME), NULL;

    if ( !(l_db_ctx = DAP_NEW_Z(dap_db_ctx_t)) )                            /* Allocate zeroed memory for new context */
        return  log_it(L_ERROR, "Cannot allocate DB context for '%s', errno=%d", a_group, errno), NULL;

    memcpy(l_db_ctx->name,  a_group, l_db_ctx->namelen = l_rc);             /* Store group name in the DB context */

    /*
    ** Start transaction, create table, commit.
    */
    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
        return  log_it(L_CRITICAL, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;

    if  ( MDBX_SUCCESS != (l_rc = mdbx_dbi_open(l_db_ctx->txn, a_group, a_flags, &l_db_ctx->dbi)) )
        return  log_it(L_CRITICAL, "mdbx_dbi_open: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;

    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
        return  log_it(L_CRITICAL, "mdbx_txn_commit: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;


    /*
    ** Add new DB Context for the group into the hash for quick access
    */
    assert( !pthread_rwlock_wrlock(&s_db_rwlock) );                         /* Get WR lock for the hash-table */

    l_db_ctx2 = NULL;
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx2);                           /* Check for existence of group again!!! */

    if ( !l_db_ctx2)                                                        /* Still not exist - fine, add new record */
        HASH_ADD_KEYPTR(hh, s_db_ctxs, l_db_ctx->name, l_db_ctx->namelen, l_db_ctx);

    assert( !pthread_rwlock_unlock(&s_db_rwlock) );

    if ( l_db_ctx2 )                                                        /* Relese unnecessary new context */
        DAP_DEL_Z(l_db_ctx);

    return l_db_ctx2 ? l_db_ctx2 : l_db_ctx;
}



static  int s_deinit(void)
{
dap_db_ctx_t *l_db_ctx = NULL, *l_tmp;

    assert ( !pthread_rwlock_wrlock(&s_db_rwlock) );                        /* Prelock for WR */

    HASH_ITER(hh, s_db_ctxs, l_db_ctx, l_tmp)
    {
        if (l_db_ctx->txn)
            mdbx_txn_abort(l_db_ctx->txn);

        if (l_db_ctx->dbi)
            mdbx_dbi_close(s_mdbx_env, l_db_ctx->dbi);

        if (s_mdbx_env)
            mdbx_env_close(s_mdbx_env);

        HASH_DEL(s_db_ctxs, l_db_ctx);
        DAP_DELETE(l_db_ctx);
    }

    assert ( !pthread_rwlock_unlock(&s_db_rwlock) );

    return 0;
}


int dap_db_driver_mdbx_init(const char *a_mdbx_path, dap_db_driver_callbacks_t *a_drv_callback)
{
int l_rc;
struct dirent *d;
DIR *dir;

    snprintf(s_db_path, sizeof(s_db_path), "%s/%s", a_mdbx_path, s_subdir );/* Make a path to MDBX root */
    dap_mkdir_with_parents(s_db_path);                                      /* Create directory for the MDBX storage */

    log_it(L_NOTICE, "Directory '%s' will be used as an location for MDBX database files", s_db_path);
    if ( MDBX_SUCCESS != (l_rc = mdbx_env_create(&s_mdbx_env)) )
        return  log_it(L_CRITICAL, "mdbx_env_create: (%d) %s", l_rc, mdbx_strerror(l_rc)), -ENOENT;

    log_it(L_NOTICE, "Set maximum number of local groups: %d", DAP_DB$K_MAXGROUPS);
    assert ( !mdbx_env_set_maxdbs (s_mdbx_env, DAP_DB$K_MAXGROUPS) );       /* Set maximum number of the file-tables (MDBX subDB)
                                                                              according to number of supported groupes */


                                                                            /* We set "unlim" for all MDBX characteristics at the moment */
    if ( MDBX_SUCCESS != (l_rc = mdbx_env_set_geometry(s_mdbx_env, 0, -1, -1, -1,-1, -1)) )
        return  log_it (L_CRITICAL, "mdbx_env_set_geometry (%s): (%d) %s", s_db_path, l_rc, mdbx_strerror(l_rc)),  -EINVAL;

    if ( MDBX_SUCCESS != (l_rc = mdbx_env_open(s_mdbx_env, s_db_path, MDBX_CREATE | MDBX_COALESCE | MDBX_LIFORECLAIM, 0664)) )
        return  log_it (L_CRITICAL, "mdbx_env_open (%s): (%d) %s", s_db_path, l_rc, mdbx_strerror(l_rc)),  -EINVAL;


    /* Scan target MDBX directory and open MDBX database for every file-local-group */
    if ( !(dir = opendir(s_db_path)) )
        return log_it(L_ERROR, "Couldn't open DB directory '%s', errno=%d", s_db_path, errno), -errno;

    while ( (d = readdir(dir)))
    {
#ifdef _DIRENT_HAVE_D_TYPE
        if (d->d_type != DT_DIR)
            continue;
#elif defined(DAP_OS_LINUX)
        struct _stat buf;
        int res = _stat(d->d_name, &buf);
        if (!S_ISDIR(buf.st_mode) || !res) {
            continue;
        }
#elif defined (DAP_OS_BSD)
        struct stat buf;
        int res = stat(d->d_name, &buf);
        if (!S_ISDIR(buf.st_mode) || !res) {
            continue;
        }
#endif
        if ( (d->d_name[0] == '.') || !dap_strcmp(d->d_name, ".."))
            continue;

        if ( !s_db_ctx_init_by_group(d->d_name, 0) )
            {
            s_deinit();
            closedir(dir);
            return -ENOENT;
        }
    }
    closedir(dir);

#if     __SYS$STARLET__
    s_db_ctx_init_by_group("test", 0);
    s_db_ctx_init_by_group("test2", 0);
#endif  /* __SYS$STARLET__ */

    /*
    ** Fill the Driver Interface Table
    */
    a_drv_callback->apply_store_obj     = s_apply_store_obj;
    a_drv_callback->read_last_store_obj = s_read_last_store_obj;

    a_drv_callback->read_store_obj      = s_read_store_obj;
    a_drv_callback->read_cond_store_obj = s_read_cond_store_obj;
    a_drv_callback->read_count_store    = s_read_count_store;
    a_drv_callback->get_groups_by_mask  = s_get_groups_by_mask;
    a_drv_callback->is_obj              = s_is_obj;
    a_drv_callback->deinit              = s_deinit;
    a_drv_callback->flush               = s_flush;
    a_drv_callback->db_ctx              = NULL;

    return MDBX_SUCCESS;
}



/**
 * @brief Serialize key and val to a item
 * key -> key
 * val[0..8] => id
 * val[..] => value_len
 * val[..] => value
 * val[..] => timestamp
 * @param a_obj a pointer to a item
 * @param key a key
 * @param val a serialize string
 */
static void s_serialize_val_to_dap_store_obj
(
        dap_store_obj_t *a_obj,
        const char *key,
        const char *val)
{
int offset = 0;

    if (!key)
        return;

    a_obj->key = dap_strdup(key);
    a_obj->id = dap_hex_to_uint(val, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    a_obj->flags = dap_hex_to_uint(val + offset, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    a_obj->value_len = dap_hex_to_uint(val + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    if (a_obj->value_len) {
        a_obj->value = DAP_NEW_SIZE(uint8_t, a_obj->value_len);
        memcpy((byte_t *)a_obj->value, val + offset, a_obj->value_len);
    }

    offset += a_obj->value_len;
    a_obj->timestamp = dap_hex_to_uint(val + offset, sizeof(uint64_t));
}

/** A callback function designed for finding a last item */
static int s_get_last_obj_iter_callback(
        void *arg,
        const char *key,
        int ksize,
        const char *val,
        int vsize,
        uint32_t expire,
        uint64_t oid)
{
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    if (--((obj_arg *)arg)->q == 0) {
        s_serialize_val_to_dap_store_obj((pdap_store_obj_t)(((obj_arg *)arg)->o), key, val);
        return false;
    }

    return true;
}

//** A callback function designed for finding a some items */
static int dap_mdbx_get_some_obj_iter_callback(
        void *arg,
        const char *key,
        int ksize,
        const char *val,
        int vsize,
        uint32_t expire,
        uint64_t oid)
{
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    dap_store_obj_t *l_obj = (dap_store_obj_t *)((obj_arg *)arg)->o;
    s_serialize_val_to_dap_store_obj(&l_obj[((obj_arg *)arg)->n - ((obj_arg *)arg)->q], key, val);
    if (--((obj_arg *)arg)->q == 0) {
        return false;
    }
    return true;
}

//** A callback function designed for finding a some items by conditionals */
static int  dap_mdbx_get_cond_obj_iter_callback(
        void *arg,
        const char *key,
        int ksize,
        const char *val,
        int vsize,
        uint32_t expire,
        uint64_t oid)
{
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    if (dap_hex_to_uint(val, sizeof(uint64_t)) < ((obj_arg *)arg)->id) {
        return true;
    }
    pdap_store_obj_t l_obj = (pdap_store_obj_t)((obj_arg *)arg)->o;
    s_serialize_val_to_dap_store_obj(&l_obj[((obj_arg *)arg)->n - ((obj_arg *)arg)->q], key, val);
    if (--((obj_arg *)arg)->q == 0) {
        return false;
    }
    return true;
}

//** A callback function designed for counting items*/
bool dap_mdbx_get_count_iter_callback(
        void *arg,
        const char *key,
        int ksize,
        const char *val,
        int vsize,
        uint32_t expire,
        uint64_t oid)
{
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);
    UNUSED(key);

    if (dap_hex_to_uint(val, sizeof(uint64_t)) < ((obj_arg *)arg)->id)
        return true;

    if (--((obj_arg *)arg)->q == 0)
        return false;

    return true;
}


/**
 * @brief Gets CDB by a_group.
 * @param a_group a group name
 * @return if CDB is found, a pointer to CDB, otherwise NULL.
 */
static  dap_db_ctx_t  *s_get_db_ctx_by_group(const char *a_group)
{
dap_db_ctx_t *l_db_ctx = NULL;

    assert ( !pthread_rwlock_rdlock(&s_db_rwlock) );
    HASH_FIND_STR(s_db_ctxs, a_group, l_db_ctx);
    assert ( !pthread_rwlock_unlock(&s_db_rwlock) );

    if ( !l_db_ctx )
        log_it(L_ERROR, "No DB context for the group '%s'", a_group);

    return l_db_ctx;
}

/**
 * @brief Flushing CDB to the disk.
 * @return 0
 */
static  int s_flush(void)
{
    return  log_it(L_DEBUG, "Flushing CDB to disk"), 0;
}

/**
 * @brief Read last store item from CDB.
 * @param a_group a group name
 * @return If successful, a pointer to item, otherwise NULL.
 */
dap_store_obj_t *s_read_last_store_obj(const char* a_group)
{
dap_db_ctx_t *l_db_ctx;

    if (!a_group)
        return NULL;

    if (!(l_db_ctx = s_get_db_ctx_by_group(a_group)) )
        return NULL;
#if 0
    void *l_iter = cdb_iterate_new(l_cdb, 0);
    obj_arg l_arg;

    l_arg.o = DAP_NEW_Z(dap_store_obj_t);
    l_arg.q = l_cdb_stat.rnum;

    cdb_iterate(l_cdb, dap_mdbx_get_last_obj_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(l_cdb, l_iter);
    l_arg.o->group = dap_strdup(a_group);


    return l_arg.o;
#endif

}

/**
 * @brief Checks if CDB has a_key
 * @param a_group the group name
 * @param a_key the key
 * @return true or false
 */
int s_is_obj(const char *a_group, const char *a_key)
{
bool l_ret = false;
dap_db_ctx_t l_db_ctx;
#if 0
CDB *l_cdb = l_db_ctx->cdb;

    if(!a_group)
        return false;

    if ( !(l_db_ctx = s_get_db_ctx_by_group(a_group)) )
        return false;

    if(a_key) {
        //int l_vsize;
        if( !cdb_is(l_cdb, a_key, (int) dap_strlen(a_key)) )
            l_ret = true;
    }
#endif
    return l_ret;
}


/**
 * @brief Gets items from CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @param a_count_out[in] a count of items
 * @param a_count[out] a count of items were got
 * @return If successful, pointer to items, otherwise NULL.
 */
static dap_store_obj_t  *s_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out)
{
    if (!a_group) {
        return NULL;
    }
    dap_db_ctx_t *l_db_ctx = s_get_db_ctx_by_group(a_group);
    if (!l_db_ctx) {
        return NULL;
    }


#if 0
    CDB *l_cdb = l_db_ctx->cdb;
    uint64_t l_count_out = 0;
    if(a_count_out) {
        l_count_out = *a_count_out;
    }
    CDBSTAT l_cdb_stat;
    cdb_stat(l_cdb, &l_cdb_stat);

    if (l_count_out == 0 || l_count_out > l_cdb_stat.rnum) {
        l_count_out = l_cdb_stat.rnum;
    }
    obj_arg l_arg;
    l_arg.o = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count_out * sizeof(dap_store_obj_t));
    l_arg.n = l_count_out;
    l_arg.q = l_count_out;
    l_arg.id = a_id;
    void *l_iter = cdb_iterate_new(l_cdb, 0);
    /*l_count_out = */cdb_iterate(l_cdb, dap_mdbx_get_cond_obj_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(l_cdb, l_iter);
    if (l_arg.q > 0) {
        l_count_out = l_arg.n - l_arg.q;
        void *tmp = DAP_REALLOC(l_arg.o, l_count_out * sizeof(dap_store_obj_t));
        if (!tmp && l_count_out) {
            log_it(L_CRITICAL, "Couldn't re-allocate memory for portion of store objects!");
            DAP_DELETE(l_arg.o);
            return NULL;
        }
        l_arg.o = tmp;
    }
    if(a_count_out) {
        *a_count_out = l_count_out;
    }
    for (uint64_t i = 0; i < l_count_out; ++i) {
        l_arg.o[i].group = dap_strdup(a_group);
    }
    return l_arg.o;
#endif
}


/**
 * @brief Reads count of items in CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @return If successful, count of store items; otherwise 0.
 */
size_t  s_read_count_store(const char *a_group, uint64_t a_id)
{
    if (!a_group) {
        return 0;
    }
#if 0
    dap_db_ctx_t l_db_ctx = s_get_db_by_group(a_group);
    if (!l_db_ctx) {
        return 0;
    }
    CDB *l_cdb = l_db_ctx->cdb;
    CDBSTAT l_cdb_stat;
    cdb_stat(l_cdb, &l_cdb_stat);
    obj_arg l_arg;
    l_arg.q = l_cdb_stat.rnum;
    l_arg.id = a_id;
    void *l_iter = cdb_iterate_new(l_cdb, 0);
    cdb_iterate(l_cdb, dap_mdbx_get_count_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(l_cdb, l_iter);
    return l_cdb_stat.rnum - l_arg.q;
#endif
}

static dap_list_t  *s_get_groups_by_mask(const char *a_group_mask)
{
dap_list_t *l_ret_list;
dap_db_ctx_t *l_db_ctx, *l_db_ctx2;

    if(!a_group_mask)
        return NULL;

    assert ( !pthread_rwlock_rdlock(&s_db_rwlock) );

    HASH_ITER(hh, s_db_ctxs, l_db_ctx, l_db_ctx2) {
        if (!dap_fnmatch(a_group_mask, l_db_ctx->name, 0) )                 /* Name match a pattern/mask ? */
            l_ret_list = dap_list_prepend(l_ret_list, dap_strdup(l_db_ctx->name)); /* Add group name to output list */
    }

    assert ( !pthread_rwlock_rdlock(&s_db_rwlock) );

    return l_ret_list;
}


/*
 * Follows suffix structure is supposed to be added at end of MDBX record, so :
 * <value> + <suffix>
 */
struct  __record_suffix__ {
        uint64_t        id;
        uint64_t        flags;
        uint64_t        ts;
};

static  int s_apply_store_obj (dap_store_obj_t *a_store_obj)
{
int     l_rc = 0, l_rc2;
dap_db_ctx_t *l_db_ctx;
MDBX_val    l_key, l_data;
char    *l_val;
struct  __record_suffix__   *l_suff;

    if ( !a_store_obj || !a_store_obj->group)                               /* Sanity checks ... */
        return -EINVAL;



    if ( !(l_db_ctx = s_get_db_ctx_by_group(a_store_obj->group)) ) {        /* Get a DB context for the group */
        log_it(L_WARNING, "No DB context for the group '%s', create it ...", a_store_obj->group);
                                                                            /* Group is not found ? Try to create table for new group */
        if ( !(l_db_ctx = s_db_ctx_init_by_group(a_store_obj->group, MDBX_CREATE)) )
            return  log_it(L_WARNING, "Cannot create DB context for the group '%s'", a_store_obj->group), -EIO;

        log_it(L_NOTICE, "DB context for the group '%s' has been created", a_store_obj->group);


        if ( a_store_obj->type == DAP_DB$K_OPTYPE_DEL )                     /* Nothing to do anymore */
            return  0;
    }


    /* At this point we have got the DB Context for the table/group
     * so we are can performs a main work
     */


    if (a_store_obj->type == DAP_DB$K_OPTYPE_ADD ) {
        if( !a_store_obj->key )
            return -ENOENT;

        l_key.iov_base = (void *) a_store_obj->key;                         /* Fill IOV for MDBX key */
        l_key.iov_len =  a_store_obj->key_len ? a_store_obj->key_len : strnlen(a_store_obj->key, DAP_DB$SZ_MAXKEY);

        /*
         * Now we are ready  to form a record in next format:
         * <value> + <suffix>
         */
        l_rc = a_store_obj->value_len + sizeof(struct  __record_suffix__); /* Compute a length of the arrea to keep value+suffix */

        if ( !(l_val = DAP_NEW_Z_SIZE(char, l_rc)) )
            return  log_it(L_ERROR, "Cannot allocate memory for new records, %d octets, errno=%d", l_rc, errno), -errno;

        l_data.iov_base = l_val;                                            /* Fill IOV for MDBX data */
        l_data.iov_len = l_rc;

        /*
         * Fill suffix's fields
        */
        l_suff = (struct __record_suffix__ *) (l_val + a_store_obj->value_len);
        l_suff->flags = a_store_obj->flags;
        l_suff->ts = a_store_obj->timestamp;

        memcpy(l_val, a_store_obj->value, a_store_obj->value_len);          /* Put <value> into the record */

        /* So, finaly: start transaction, do INSERT, COMMIT or ABORT ... */
        if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
            return  DAP_FREE(l_val), log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), -EIO;


                                                                            /* Generate <sequence number> for new record */
        if ( MDBX_RESULT_TRUE != mdbx_dbi_sequence	(l_db_ctx->txn, l_db_ctx->dbi, &l_suff->id, 1) )
        {
            log_it (L_CRITICAL, "mdbx_dbi_sequence: (%d) %s", l_rc, mdbx_strerror(l_rc));

            if ( MDBX_SUCCESS != (l_rc = mdbx_txn_abort(l_db_ctx->txn)) )
                log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc));

            return  DAP_FREE(l_val), -EIO;
        }



        if ( MDBX_SUCCESS != (l_rc = mdbx_put(l_db_ctx->txn, l_db_ctx->dbi, &l_key, &l_data, 0)) )
        {
            log_it (L_ERROR, "mdbx_put: (%d) %s", l_rc, mdbx_strerror(l_rc));

            if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_abort(l_db_ctx->txn)) )
                log_it (L_ERROR, "mdbx_abort: (%d) %s", l_rc2, mdbx_strerror(l_rc2));
        }
        else if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
            log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc));

        if ( l_rc != MDBX_SUCCESS )
            DAP_FREE(l_val);

        return ( l_rc == MDBX_SUCCESS ) ? 0 : -EIO;
    } /* DAP_DB$K_OPTYPE_ADD */



    if (a_store_obj->type == DAP_DB$K_OPTYPE_DEL)  {
        if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, 0, &l_db_ctx->txn)) )
            return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), -ENOENT;


        if ( a_store_obj->key ) {                                           /* Delete record */
                l_key.iov_base = (void *) a_store_obj->key;
                l_key.iov_len =  a_store_obj->key_len ? a_store_obj->key_len : strnlen(a_store_obj->key, DAP_DB$SZ_MAXKEY);

                if ( MDBX_SUCCESS != (l_rc = mdbx_del(l_db_ctx->txn, l_db_ctx->dbi, &l_key, NULL)) )
                    l_rc2 = -EIO, log_it (L_ERROR, "mdbx_del: (%d) %s", l_rc, mdbx_strerror(l_rc));
            }
        else {                                                              /* Truncate whole table */
                if ( MDBX_SUCCESS != (l_rc = mdbx_drop(l_db_ctx->txn, l_db_ctx->dbi, 0)) )
                    l_rc2 = -EIO, log_it (L_ERROR, "mdbx_drop: (%d) %s", l_rc, mdbx_strerror(l_rc));
            }

        if ( l_rc != MDBX_SUCCESS ) {                                       /* Check result of mdbx_drop/del */
            if ( MDBX_SUCCESS != (l_rc = mdbx_txn_abort(l_db_ctx->txn)) )
                l_rc2 = -EIO, log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc));
        }
        else if ( MDBX_SUCCESS != (l_rc = mdbx_txn_commit(l_db_ctx->txn)) )
            l_rc2 = -EIO, log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc, mdbx_strerror(l_rc));

        return ( l_rc2 == MDBX_SUCCESS ) ? 0 : -EIO;
    } /* DAP_DB$K_OPTYPE_DEL */

    log_it (L_ERROR, "Unhandle/unknow DB opcode (%d/%#x)", a_store_obj->type, a_store_obj->type);

    return  -EIO;
}







/**
 * @brief Gets items from CDB by a_group and a_key. If a_key=NULL then gets a_count_out items.
 * @param a_group the group name
 * @param a_key the key or NULL
 * @param a_count_out IN. Count of read items. OUT Count of items was read
 * @return If successful, pointer to items; otherwise NULL.
 */
static dap_store_obj_t *s_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out)
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

    if ( (l_db_ctx = s_get_db_ctx_by_group(a_group)) )                      /* Get free DB Context */
        return NULL;



    if ( MDBX_SUCCESS != (l_rc = mdbx_txn_begin(s_mdbx_env, NULL, MDBX_TXN_RDONLY, &l_db_ctx->txn)) )
        return  log_it (L_ERROR, "mdbx_txn_begin: (%d) %s", l_rc, mdbx_strerror(l_rc)), NULL;



    /*
     *  Perfroms a find/get a record with the given key
     */
    if ( a_key )
    {
        l_key.iov_base = (void *) a_key;                                    /* Fill IOV for MDBX key */
        l_key.iov_len =  strlen(a_key);

        if ( MDBX_SUCCESS == (l_rc = mdbx_get(l_db_ctx->txn, l_db_ctx->dbi, &l_key, &l_data)) )
        {
            /* Found ! Allocate memory to <store object> < and <value> */
            if ( (l_obj = DAP_CALLOC(1, sizeof( dap_store_obj_t ))) )
            {
                if ( (l_obj->value = DAP_MALLOC((l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
                    {
                    /* Fill the <store obj> by data from the retreived record */
                    l_obj->value = ((uint8_t *) l_obj) + sizeof( dap_store_obj_t );

                    l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
                    memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

                    l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
                    l_obj->id = l_suff->id;
                    l_obj->timestamp = l_suff->ts;
                    l_obj->flags = l_suff->flags;
                }
                else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
            }
            else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object, errno=%d", errno);
        } else if ( l_rc != MDBX_NOTFOUND)
            log_it (L_ERROR, "mdbx_get: (%d) %s", l_rc, mdbx_strerror(l_rc));

        if ( MDBX_SUCCESS != (l_rc2 = mdbx_txn_abort(l_db_ctx->txn)) )
            log_it (L_ERROR, "mdbx_txn_abort: (%d) %s", l_rc2, mdbx_strerror(l_rc2));

        if ( l_rc != MDBX_SUCCESS ) {
            DAP_FREE(l_obj->value);
            DAP_DEL_Z(l_obj);
        }

        return ( l_rc == MDBX_SUCCESS ) ? l_obj : NULL;
    }




    /*
    ** If a_key is NULL - retreive a requestd number of recrods from the table
    */
    do  {
        l_count_out = a_count_out? *a_count_out : DAP_DB$K_MAXOBJS;             /* Limit a number of objects to be returned */
        *a_count_out = 0;

        /*
         * Retrive statistic for group/table, we need to compute a number of records can be retreived
         */
        l_rc2 = 0;
        if ( MDBX_SUCCESS != (l_rc = mdbx_dbi_stat	(l_db_ctx->txn, l_db_ctx->dbi, &l_stat, sizeof(MDBX_stat))) ) {
            log_it (L_ERROR, "mdbx_dbi_stat: (%d) %s", l_rc2, mdbx_strerror(l_rc2));
            break;
        }

        if ( !(l_count_out = min(l_stat.ms_entries, l_count_out)) ) {
            log_it(L_WARNING, "No object (-s) to be rtreived from the group '%s'", a_group);
            break;
        }

        /*
         * Allocate memory for array of returned objects
        */
        l_rc2 = l_count_out * sizeof(dap_store_obj_t);
        if ( !(l_obj_arr = DAP_NEW_Z_SIZE(char, l_rc2)) ) {
            log_it(L_ERROR, "Cannot allocate %zu octets for %d store objects",
                   l_count_out * sizeof(dap_store_obj_t), l_count_out);
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
            if ( (l_obj->value = DAP_MALLOC((l_data.iov_len + 1)  - sizeof(struct __record_suffix__))) )
                {
                /* Fill the <store obj> by data from the retreived record */
                l_obj->value = ((uint8_t *) l_obj) + sizeof( dap_store_obj_t );

                l_obj->value_len = l_data.iov_len - sizeof(struct __record_suffix__);
                memcpy(l_obj->value, l_data.iov_base, l_obj->value_len);

                l_suff = (struct __record_suffix__ *) (l_data.iov_base + l_obj->value_len);
                l_obj->id = l_suff->id;
                l_obj->timestamp = l_suff->ts;
                l_obj->flags = l_suff->flags;
                }
            else l_rc = MDBX_PROBLEM, log_it (L_ERROR, "Cannot allocate a memory for store object value, errno=%d", errno);
        }

        if ( (MDBX_SUCCESS != l_rc) && (l_rc != MDBX_NOTFOUND) )
        {
          log_it (L_ERROR, "mdbx_cursor_get: (%d) %s", l_rc, mdbx_strerror(l_rc)), l_rc = MDBX_SUCCESS;
          break;
        }
    } while (0);

    if (l_cursor)
        mdbx_cursor_close(l_cursor);
    if (l_db_ctx->txn)
        mdbx_txn_abort(l_db_ctx->txn);

    return l_obj_arr;
}
