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

#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <uthash.h>
#define _GNU_SOURCE

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_strfuncs.h" // #include <dap_fnmatch.h>
#include "dap_chain_global_db_driver_cdb.h"
#include "dap_file_utils.h"

#define LOG_TAG "dap_chain_global_db_cdb"

/** Struct for a item */
typedef struct _obj_arg {
    pdap_store_obj_t o;
    uint64_t q;
    uint64_t n;
    uint64_t id;
} obj_arg, *pobj_arg;

/** Struct for a CDB instanse */
typedef struct _cdb_instance {
    CDB *cdb;
    char *local_group;
    uint64_t id;
    UT_hash_handle hh;
} cdb_instance, *pcdb_instance;

/** A path to a CDB file. */
static char *s_cdb_path = NULL;
/** A pointer to a CDB instance. */
static pcdb_instance s_cdb = NULL;
/** A mutex for working with a CDB instanse. */
static pthread_mutex_t cdb_mutex = PTHREAD_MUTEX_INITIALIZER;
/** A read-write lock for working with a CDB instanse. */
static pthread_rwlock_t cdb_rwlock = PTHREAD_RWLOCK_INITIALIZER;

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
static void cdb_serialize_val_to_dap_store_obj(pdap_store_obj_t a_obj, const char *key, const char *val) {
    if (!key || !val) {
        a_obj = NULL;
        return;
    }
    int offset = 0;
    a_obj->key = dap_strdup(key);
    a_obj->id = dap_hex_to_uint(val, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    a_obj->value_len = dap_hex_to_uint(val + offset, sizeof(unsigned long));
    offset += sizeof(unsigned long);
    a_obj->value = DAP_NEW_SIZE(uint8_t, a_obj->value_len);
    memcpy(a_obj->value, val + offset, a_obj->value_len);
    offset += a_obj->value_len;
    a_obj->timestamp = (time_t)dap_hex_to_uint(val + offset, sizeof(time_t));
}

/** A callback function designed for finding a last item */
bool dap_cdb_get_last_obj_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    if (--((pobj_arg)arg)->q == 0) {
        cdb_serialize_val_to_dap_store_obj((pdap_store_obj_t)(((pobj_arg)arg)->o), key, val);
        return false;
    }
    return true;
}

//** A callback function designed for finding a some items */
bool dap_cdb_get_some_obj_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    pdap_store_obj_t l_obj = (pdap_store_obj_t)((pobj_arg)arg)->o;
    cdb_serialize_val_to_dap_store_obj(&l_obj[((pobj_arg)arg)->n - ((pobj_arg)arg)->q], key, val);
    if (--((pobj_arg)arg)->q == 0) {
        return false;
    }
    return true;
}

//** A callback function designed for finding a some items by conditionals */
bool dap_cdb_get_cond_obj_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);

    if (dap_hex_to_uint(val, sizeof(uint64_t)) < ((pobj_arg)arg)->id) {
        return true;
    }
    pdap_store_obj_t l_obj = (pdap_store_obj_t)((pobj_arg)arg)->o;
    cdb_serialize_val_to_dap_store_obj(&l_obj[((pobj_arg)arg)->n - ((pobj_arg)arg)->q], key, val);
    if (--((pobj_arg)arg)->q == 0) {
        return false;
    }
    return true;
}

//** A callback function designed for countng items*/
bool dap_cdb_get_count_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    UNUSED(ksize);
    UNUSED(val);
    UNUSED(vsize);
    UNUSED(expire);
    UNUSED(oid);
    UNUSED(key);

    if (dap_hex_to_uint(val, sizeof(uint64_t)) < ((pobj_arg)arg)->id) {
        return true;
    }
    if (--((pobj_arg)arg)->q == 0) {
        return false;
    }
    return true;
}

/** 
 * @brief Initiates a CDB with main hash table size: 1000000,
 * record cache: 128Mb, index page cache: 1024Mb.
 * @param a_group a group name 
 * @param a_flags should be combination of CDB_CREAT / CDB_TRUNC / CDB_PAGEWARMUP 
   CDB_PAGEWARMUP
 * @return A pointer to CDB, if success. NULL, if error.
 */
pcdb_instance dap_cdb_init_group(char *a_group, int a_flags) {
    pcdb_instance l_cdb_i = NULL;
    pthread_mutex_lock(&cdb_mutex);
    char l_cdb_path[strlen(s_cdb_path) + strlen(a_group) + 2];
    HASH_FIND_STR(s_cdb, a_group, l_cdb_i);
    if (l_cdb_i && !(a_flags & CDB_TRUNC)) {
        goto FIN;
    }
    l_cdb_i = DAP_NEW(cdb_instance);
    l_cdb_i->local_group = dap_strdup(a_group);
    l_cdb_i->cdb = cdb_new();
    memset(l_cdb_path, '\0', sizeof(l_cdb_path));
    dap_snprintf(l_cdb_path, sizeof(l_cdb_path), "%s/%s", s_cdb_path, a_group);
    cdb_options l_opts = { 1000000, 128, 1024 };
    if (cdb_option(l_cdb_i->cdb, l_opts.hsize, l_opts.pcacheMB, l_opts.rcacheMB) != CDB_SUCCESS) {
        log_it(L_ERROR, "Options are inacceptable: \"%s\"", cdb_errmsg(cdb_errno(l_cdb_i->cdb)));
        goto ERR;
    }
    if (cdb_open(l_cdb_i->cdb, l_cdb_path, a_flags) != CDB_SUCCESS) {
        log_it(L_ERROR, "An error occured while opening CDB: \"%s\"", cdb_errmsg(cdb_errno(l_cdb_i->cdb)));
        goto ERR;
    }
    if (!(a_flags & CDB_TRUNC)) {
        CDBSTAT l_cdb_stat;
        cdb_stat(l_cdb_i->cdb, &l_cdb_stat);
        if (l_cdb_stat.rnum > 0 || !(a_flags & CDB_CREAT)) {
            void *l_iter = cdb_iterate_new(l_cdb_i->cdb, 0);
            obj_arg l_arg;
            l_arg.o = DAP_NEW_Z(dap_store_obj_t);
            l_arg.q = l_cdb_stat.rnum;
            cdb_iterate(l_cdb_i->cdb, dap_cdb_get_last_obj_iter_callback, (void*)&l_arg, l_iter);
            cdb_iterate_destroy(l_cdb_i->cdb, l_iter);
            l_cdb_i->id = l_arg.o->id;
            //log_it(L_INFO, "Group \"%s\" found"             , l_cdb_i->local_group);
            //log_it(L_INFO, "Records: %-24u"                 , l_cdb_stat.rnum);
            //log_it(L_INFO, "Average read latency: %-24u"    , l_cdb_stat.rlatcy);
            //log_it(L_INFO, "Average write latency: %-24u"   , l_cdb_stat.wlatcy);
            //log_it(L_INFO, "Last id: %-24u"                 , l_cdb_i->id);
            DAP_DELETE(l_arg.o);
        } else {
            log_it(L_INFO, "Group \"%s\" created"           , l_cdb_i->local_group);
            l_cdb_i->id = 0;
        }
        HASH_ADD_KEYPTR(hh, s_cdb, l_cdb_i->local_group, strlen(l_cdb_i->local_group), l_cdb_i);
    } else {
        log_it(L_INFO, "Group \"%s\" truncated"             , l_cdb_i->local_group);
        l_cdb_i->id = 0;
    }

FIN:
    pthread_mutex_unlock(&cdb_mutex);
    return l_cdb_i;
ERR:
    cdb_destroy(l_cdb_i->cdb);
    DAP_DELETE(l_cdb_i->local_group);
    DAP_DELETE(l_cdb_i);
    pthread_mutex_unlock(&cdb_mutex);
    return NULL;
}

/**
 * @brief Initiates a CDB with callback fuctions.
 * @param a_cdb_path a path to CDB. Saved in s_cdb_path
 * @param a_drv_callback a struct for callback functions
 * @return 0 if success, -1 if сouldn't open db directory, -2 if dap_cdb_init_group() returns NULL.
 */
int dap_db_driver_cdb_init(const char *a_cdb_path, dap_db_driver_callbacks_t *a_drv_callback) {
    s_cdb_path = dap_strdup(a_cdb_path);
    if(s_cdb_path[strlen(s_cdb_path)] == '/') {
        s_cdb_path[strlen(s_cdb_path)] = '\0';
    }
    dap_mkdir_with_parents(s_cdb_path);
    struct dirent *d;
    DIR *dir = opendir(s_cdb_path);
    if (!dir) {
        log_it(L_ERROR, "Couldn't open db directory");
        return -1;
    }
    for (d = readdir(dir); d; d = readdir(dir)) {
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
        if (!dap_strcmp(d->d_name, ".") || !dap_strcmp(d->d_name, "..")) {
            continue;
        }
        pcdb_instance l_cdb_i = dap_cdb_init_group(d->d_name, CDB_PAGEWARMUP);
        if (!l_cdb_i) {
            dap_db_driver_cdb_deinit();
            closedir(dir);
            return -2;
        }
    }
    a_drv_callback->read_last_store_obj = dap_db_driver_cdb_read_last_store_obj;
    a_drv_callback->apply_store_obj     = dap_db_driver_cdb_apply_store_obj;
    a_drv_callback->read_store_obj      = dap_db_driver_cdb_read_store_obj;
    a_drv_callback->read_cond_store_obj = dap_db_driver_cdb_read_cond_store_obj;
    a_drv_callback->read_count_store    = dap_db_driver_cdb_read_count_store;
    a_drv_callback->get_groups_by_mask  = dap_db_driver_cdb_get_groups_by_mask;
    a_drv_callback->is_obj              = dap_db_driver_cdb_is_obj;
    a_drv_callback->deinit              = dap_db_driver_cdb_deinit;
    a_drv_callback->flush               = dap_db_driver_cdb_flush;

    closedir(dir);
    return CDB_SUCCESS;
}

/**
 * @brief Gets CDB by a_group.
 * @param a_group a group name
 * @return if CDB is found, a pointer to CDB, otherwise NULL.
 */ 
pcdb_instance dap_cdb_get_db_by_group(const char *a_group) {
    pcdb_instance l_cdb_i = NULL;
    pthread_rwlock_rdlock(&cdb_rwlock);
    HASH_FIND_STR(s_cdb, a_group, l_cdb_i);
    pthread_rwlock_unlock(&cdb_rwlock);
    return l_cdb_i;
}

/**
 * @brief Creates a directory on the path s_cdb_path/a_group.
 * @param a_group the group name
 * @return 0
 */
int dap_cdb_add_group(const char *a_group) {
    char l_cdb_path[strlen(s_cdb_path) + strlen(a_group) + 2];
    memset(l_cdb_path, '\0', sizeof(l_cdb_path));
    dap_snprintf(l_cdb_path, sizeof(l_cdb_path), "%s/%s", s_cdb_path, a_group);
#ifdef _WIN32
    mkdir(l_cdb_path);
#else
    mkdir(l_cdb_path, 0755);
#endif
    return 0;
}

/**
 * @brief Deinitialize CDB.
 * @return 0
 */
int dap_db_driver_cdb_deinit() {
    pcdb_instance cur_cdb, tmp;
    pthread_rwlock_wrlock(&cdb_rwlock);
    HASH_ITER(hh, s_cdb, cur_cdb, tmp) {
        DAP_DELETE(cur_cdb->local_group);
        cdb_destroy(cur_cdb->cdb);
        HASH_DEL(s_cdb, cur_cdb);
        DAP_DELETE(cur_cdb);
    }
    pthread_rwlock_unlock(&cdb_rwlock);
    DAP_DEL_Z(s_cdb_path)
    return CDB_SUCCESS;
}

/**
 * @brief Flushing CDB to the disk.
 * @return 0
 */
int dap_db_driver_cdb_flush(void) {
    int ret = 0;
    log_it(L_DEBUG, "Flushing CDB to disk");
    cdb_instance *cur_cdb, *tmp;
    pthread_rwlock_rdlock(&cdb_rwlock);
    HASH_ITER(hh, s_cdb, cur_cdb, tmp) {
        cdb_flushalldpage(cur_cdb->cdb);
    }
    pthread_rwlock_unlock(&cdb_rwlock);
    log_it(L_DEBUG, "All data dumped");
    return ret;
}

/**
 * @brief Read last store item from CDB.
 * @param a_group a group name
 * @return If successful, a pointer to item, otherwise NULL.
 */  
dap_store_obj_t *dap_db_driver_cdb_read_last_store_obj(const char* a_group) {
    if (!a_group) {
        return NULL;
    }
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_group);
    if (!l_cdb_i) {
        return NULL;
    }
    CDB *l_cdb = l_cdb_i->cdb;
    CDBSTAT l_cdb_stat;
    cdb_stat(l_cdb, &l_cdb_stat);
    void *l_iter = cdb_iterate_new(l_cdb, 0);
    obj_arg l_arg;
    l_arg.o = DAP_NEW_Z(dap_store_obj_t);
    l_arg.q = l_cdb_stat.rnum;
    cdb_iterate(l_cdb, dap_cdb_get_last_obj_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(l_cdb, l_iter);
    l_arg.o->group = dap_strdup(a_group);
    return l_arg.o;
}

/**
 * @brief Checks if CDB has a_key
 * @param a_group the group name
 * @param a_key the key
 * @return true or false
 */  
bool dap_db_driver_cdb_is_obj(const char *a_group, const char *a_key)
{
    bool l_ret = false;
    if(!a_group) {
        return false;
    }
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_group);
    if(!l_cdb_i) {
        return false;
    }
    CDB *l_cdb = l_cdb_i->cdb;
    if(a_key) {
        //int l_vsize;
        if(!cdb_is(l_cdb, a_key, (int) dap_strlen(a_key)))
            l_ret = true;
    }
    return l_ret;
}

/**
 * @brief Gets items from CDB by a_group and a_key. If a_key=NULL then gets a_count_out items.
 * @param a_group the group name
 * @param a_key the key or NULL
 * @param a_count_out IN. Count of read items. OUT Count of items was read
 * @return If successful, pointer to items; otherwise NULL.
 */  
dap_store_obj_t *dap_db_driver_cdb_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out) {
    if (!a_group) {
        return NULL;
    }
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_group);
    if (!l_cdb_i) {
        return NULL;
    }
    CDB *l_cdb = l_cdb_i->cdb;
    dap_store_obj_t *l_obj = NULL;
    if (a_key) {
        char *l_value;
        int l_vsize;
        cdb_get(l_cdb, a_key, (int)strlen(a_key), (void**)&l_value, &l_vsize);
        if (!l_value) {
            return NULL;
        }
        l_obj = DAP_NEW_Z(dap_store_obj_t);
        cdb_serialize_val_to_dap_store_obj(l_obj, a_key, l_value);
        l_obj->group = dap_strdup(a_group);
        cdb_free_val((void**)&l_value);
        if(a_count_out) {
            *a_count_out = 1;
        }
    } else {
        uint64_t l_count_out = 0;
        if(a_count_out) {
            l_count_out = *a_count_out;
        }
        CDBSTAT l_cdb_stat;
        cdb_stat(l_cdb, &l_cdb_stat);
        if ((l_count_out == 0) || (l_count_out > l_cdb_stat.rnum)) {
            l_count_out = l_cdb_stat.rnum;
        }
        obj_arg l_arg;
        l_arg.o = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count_out * sizeof(dap_store_obj_t));
        l_arg.q = l_count_out;
        l_arg.n = l_count_out;
        void *l_iter = cdb_iterate_new(l_cdb, 0);
        /*l_count_out = */cdb_iterate(l_cdb, dap_cdb_get_some_obj_iter_callback, (void*)&l_arg, l_iter);
        cdb_iterate_destroy(l_cdb, l_iter);
        if(a_count_out) {
            *a_count_out = l_count_out;
        }
        for (uint64_t i = 0; i < l_count_out; ++i) {
            l_arg.o[i].group = dap_strdup(a_group);
        }
        l_obj = l_arg.o;
    }
    return l_obj;
}

/**
 * @brief Gets items from CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @param a_count_out[in] a count of items
 * @param a_count[out] a count of items were got
 * @return If successful, pointer to items, otherwise NULL.
 */  
dap_store_obj_t* dap_db_driver_cdb_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out) {
    if (!a_group) {
        return NULL;
    }
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_group);
    if (!l_cdb_i) {
        return NULL;
    }
    CDB *l_cdb = l_cdb_i->cdb;
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
    /*l_count_out = */cdb_iterate(l_cdb, dap_cdb_get_cond_obj_iter_callback, (void*)&l_arg, l_iter);
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
}


/**
 * @brief Reads count of items in CDB by a_group and a_id.
 * @param a_group the group name
 * @param a_id id
 * @return If successful, count of store items; otherwise 0.
 */  
size_t dap_db_driver_cdb_read_count_store(const char *a_group, uint64_t a_id)
{
    if (!a_group) {
        return 0;
    }
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_group);
    if (!l_cdb_i) {
        return 0;
    }
    CDB *l_cdb = l_cdb_i->cdb;
    CDBSTAT l_cdb_stat;
    cdb_stat(l_cdb, &l_cdb_stat);
    obj_arg l_arg;
    l_arg.q = l_cdb_stat.rnum;
    l_arg.id = a_id;
    void *l_iter = cdb_iterate_new(l_cdb, 0);
    cdb_iterate(l_cdb, dap_cdb_get_count_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(l_cdb, l_iter);
    return l_cdb_stat.rnum - l_arg.q;
}

/**
 * @brief Check whether the groups match the pattern a_group_mask, which is a shell wildcard pattern.
 * @param a_group_mask the mask
 * @return If successful, pointer to dap_list with group names; otherwise NULL.
 */
dap_list_t* dap_db_driver_cdb_get_groups_by_mask(const char *a_group_mask)
{
    dap_list_t *l_ret_list = NULL;
    if(!a_group_mask)
        return NULL;
    cdb_instance *cur_cdb, *tmp;
    pthread_rwlock_rdlock(&cdb_rwlock);
    HASH_ITER(hh, s_cdb, cur_cdb, tmp) {
        char *l_table_name = cur_cdb->local_group;
        if(!dap_fnmatch(a_group_mask, l_table_name, 0))
            l_ret_list = dap_list_prepend(l_ret_list, dap_strdup(l_table_name));
    }
    pthread_rwlock_unlock(&cdb_rwlock);
    return l_ret_list;
}


/**
 * @brief Adds or deletes item in CDB depending on a_store_obj->type.
 * @param a_store_obj a pointer to the item
 * @return 0 if success, <0 error.
 */
int dap_db_driver_cdb_apply_store_obj(pdap_store_obj_t a_store_obj) {
    if(!a_store_obj || !a_store_obj->group) {
        return -1;
    }
    int ret = 0;
    pcdb_instance l_cdb_i = dap_cdb_get_db_by_group(a_store_obj->group);
    if (!l_cdb_i) {
        dap_cdb_add_group(a_store_obj->group);
        l_cdb_i = dap_cdb_init_group(a_store_obj->group, CDB_CREAT | CDB_PAGEWARMUP);
    }
    if (!l_cdb_i) {
        return -1;
    }
    if(a_store_obj->type == 'a') {
        if(!a_store_obj->key) {
            return -2;
        }
        cdb_record l_rec;
        l_rec.key = a_store_obj->key; //dap_strdup(a_store_obj->key);
        int offset = 0;
        char *l_val = DAP_NEW_Z_SIZE(char, sizeof(uint64_t) + sizeof(unsigned long) + a_store_obj->value_len + sizeof(time_t));
        dap_uint_to_hex(l_val, ++l_cdb_i->id, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        dap_uint_to_hex(l_val + offset, a_store_obj->value_len, sizeof(unsigned long));
        offset += sizeof(unsigned long);
        if(a_store_obj->value && a_store_obj->value_len){
            memcpy(l_val + offset, a_store_obj->value, a_store_obj->value_len);
            DAP_DELETE(a_store_obj->value);
        }
        offset += a_store_obj->value_len;
        unsigned long l_time = (unsigned long)a_store_obj->timestamp;
        dap_uint_to_hex(l_val + offset, l_time, sizeof(time_t));
        offset += sizeof(time_t);
        l_rec.val = l_val;
        if (cdb_set2(l_cdb_i->cdb, l_rec.key, (int)strlen(l_rec.key), l_rec.val, offset, CDB_INSERTCACHE | CDB_OVERWRITE, 0) != CDB_SUCCESS) {
            log_it(L_ERROR, "Couldn't add record with key [%s] to CDB: \"%s\"", l_rec.key, cdb_errmsg(cdb_errno(l_cdb_i->cdb)));
            ret = -1;
        }
        DAP_DELETE(l_rec.key);
        DAP_DELETE(l_rec.val);
    } else if(a_store_obj->type == 'd') {
        if(a_store_obj->key) {
            if(cdb_del(l_cdb_i->cdb, a_store_obj->key, (int) strlen(a_store_obj->key)) == -3)
                ret = 1;
        } else {
            cdb_destroy(l_cdb_i->cdb);
            if (!dap_cdb_init_group(a_store_obj->group, CDB_TRUNC | CDB_PAGEWARMUP)) {
                ret = -1;
            }
        }
        DAP_DELETE(a_store_obj->key);
    }
    return ret;
}
