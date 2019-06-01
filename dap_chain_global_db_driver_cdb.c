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
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"
#include "dap_chain_global_db_driver_cdb.h"

#define LOG_TAG "db_cdb"

#define uint64_size sizeof(uint64_t)

typedef enum {
    CDB_GROUP_LOCAL_HIST,
    CDB_GROUP_LOCAL_LAST_TS,
    CDB_GROUP_LOCAL_GEN
} CDB_group;

typedef struct _obj_arg {
    pdap_store_obj_t o;
    uint64_t q;
    uint64_t n;
} obj_arg, *pobj_arg;

static CDB **s_cdb = NULL; // TODO: instead of this, there must be a local group manager with assigned paths

static inline void dap_cdb_uint_to_hex(char *arr, uint64_t val, short size) {
    short i = 0;
    for (i = 0; i < size; ++i) {
        arr[i] = (char)(((uint64_t) val >> (8 * (size - 1 - i))) & 0xFFu);
    }
}

static inline uint64_t dap_cdb_hex_to_uint(char *arr, short size) {
    uint64_t val = 0;
    short i = 0;
    for (i = 0; i < size; ++i){
        uint8_t byte = *arr++;
        if (byte >= 'a' && byte <='f'){
            byte = byte - 'a' + 10;
        } else if (byte >= 'A' && byte <='F') {
            byte = byte - 'A' + 10;
        }
        val = (val << 8) | (byte & 0xFFu);
    }
    return val;
}

static void cdb_serialize_val_to_dap_store_obj2(pdap_store_obj_t a_obj, char *key, char *val) {
    if (!key || !val) {
        a_obj = NULL;
        return;
    }
    int offset = 0;
    a_obj->key = dap_strdup(key);

    unsigned char l_id[uint64_size] = {'\0'};
    memcpy(l_id, val, uint64_size);
    a_obj->id = dap_cdb_hex_to_uint(l_id, uint64_size);
    offset += uint64_size;

    unsigned char l_val_size[sizeof(unsigned long)] = {'\0'};
    memcpy(l_val_size, val + offset, sizeof(unsigned long));
    a_obj->value_len = dap_cdb_hex_to_uint(l_val_size, sizeof(unsigned long));
    offset += sizeof(unsigned long);

    a_obj->value = DAP_NEW_SIZE(uint8_t, a_obj->value_len);
    memcpy(a_obj->value, val + offset, a_obj->value_len);
    offset += a_obj->value_len;

    unsigned char l_rawtime[sizeof(time_t)] = {'\0'};
    memcpy(l_rawtime, val + offset, sizeof(time_t));
    a_obj->timestamp = dap_cdb_hex_to_uint(l_rawtime, sizeof(time_t));
}

bool dap_cdb_get_last_obj_iter_callback2(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    /* this is wrong! TODO: instead of 'oid' must checkout real 'arg->id' */
    /*if (oid != ((pobj_arg)arg)->q) {
        return true;
    }*/
    cdb_serialize_val_to_dap_store_obj2((pdap_store_obj_t)(((pobj_arg)arg)->o), key, val);
    return false;
}

bool dap_cdb_get_some_obj_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    ((pobj_arg)arg)->q--;
    uint64_t q = ((pobj_arg)arg)->q;
    uint64_t n = ((pobj_arg)arg)->n;
    pdap_store_obj_t l_obj = (pdap_store_obj_t)((pobj_arg)arg)->o;
    cdb_serialize_val_to_dap_store_obj2(&l_obj[n-q-1], key, val);
    if (q == 0) {
        return false;
    }
    return true;
}

bool dap_cdb_get_cond_obj_iter_callback(void *arg, const char *key, int ksize, const char *val, int vsize, uint32_t expire, uint64_t oid) {
    /* No need due to this implementation design */
}

CDB_group dap_db_cdb_define_group(const char* a_group) {
    /* turns out to be useless thing...
      TODO: create local groups on-demand */
    if (!dap_strcmp(a_group, "global.history")) {
        return CDB_GROUP_LOCAL_HIST;
    } else if (!dap_strcmp(a_group, "local.node.last_ts")) {
        return CDB_GROUP_LOCAL_LAST_TS;
    } else return CDB_GROUP_LOCAL_GEN;
}

int dap_db_driver_cdb_options(pcdb_options l_opts, CDB_group a_group) {
        if (cdb_option(s_cdb[a_group],
                       l_opts->hsize,
                       l_opts->pcacheMB,
                       l_opts->rcacheMB) != CDB_SUCCESS) return -1;
    return CDB_SUCCESS;
}

int dap_db_driver_cdb_init(const char *a_path_db, dap_db_driver_callbacks_t *a_drv_callback) {
    s_cdb = DAP_NEW_Z_SIZE(CDB*, 3 * sizeof(CDB*));
    if (!(s_cdb[CDB_GROUP_LOCAL_HIST]           = cdb_new())
            || !(s_cdb[CDB_GROUP_LOCAL_LAST_TS] = cdb_new())
            || !(s_cdb[CDB_GROUP_LOCAL_GEN]     = cdb_new()))
    {
        log_it(L_ERROR, "Couldn't initialize CDB");
        DAP_DELETE(s_cdb);
        return -1;
    }
    cdb_options l_opts = { 1000000,
                           128,
                           1024
                         };
    if ((dap_db_driver_cdb_options(&l_opts, CDB_GROUP_LOCAL_HIST) != CDB_SUCCESS)
            || (dap_db_driver_cdb_options(&l_opts, CDB_GROUP_LOCAL_LAST_TS) != CDB_SUCCESS)
            || (dap_db_driver_cdb_options(&l_opts, CDB_GROUP_LOCAL_GEN) != CDB_SUCCESS))
    {
        log_it(L_ERROR, "Specified CDB options unapplicable");
        return -2;
    }
    log_it(L_INFO, "CDB initialized");
    char *l_cdb_path = DAP_NEW_Z_SIZE(char, strlen(a_path_db) + 32);
    int ret = CDB_SUCCESS;

    memset(l_cdb_path, '\0', strlen(a_path_db) + 32);
    strcat(l_cdb_path, a_path_db);
    strcat(l_cdb_path + strlen(a_path_db), "_global_history");
    if (cdb_open(s_cdb[CDB_GROUP_LOCAL_HIST], l_cdb_path, CDB_CREAT | CDB_PAGEWARMUP) < 0) {
        log_it(L_ERROR, "CDB database couldn't be opened: \"%s\"", cdb_errmsg(cdb_errno(s_cdb[CDB_GROUP_LOCAL_HIST])));
        ret = -3;
        goto ERR;
    }

    memset(l_cdb_path + strlen(a_path_db), '\0', 32);
    strcat(l_cdb_path, "_local_node_last");
    if (cdb_open(s_cdb[CDB_GROUP_LOCAL_LAST_TS], l_cdb_path, CDB_CREAT | CDB_PAGEWARMUP) < 0) {
        log_it(L_ERROR, "CDB database couldn't be opened: \"%s\"", cdb_errmsg(cdb_errno(s_cdb[CDB_GROUP_LOCAL_LAST_TS])));
        ret = -4;
        goto ERR;
    }

    memset(l_cdb_path + strlen(a_path_db), '\0', 32);
    strcat(l_cdb_path, "_local_general");
    if (cdb_open(s_cdb[CDB_GROUP_LOCAL_GEN], l_cdb_path, CDB_CREAT | CDB_PAGEWARMUP) < 0) {
        log_it(L_ERROR, "CDB database couldn't be opened: \"%s\"", cdb_errmsg(cdb_errno(s_cdb[CDB_GROUP_LOCAL_GEN])));
        ret = -5;
        goto ERR;
    }

    CDBSTAT l_cdb_stat;
    cdb_stat(s_cdb[CDB_GROUP_LOCAL_GEN], &l_cdb_stat);
    log_it(L_INFO, "Database \"%s\" opened"         , l_cdb_path);
    log_it(L_INFO, "Records: %-24u"                 , l_cdb_stat.rnum);
    log_it(L_INFO, "Average read latency: %-24u"    , l_cdb_stat.rlatcy);
    log_it(L_INFO, "Average write latency: %-24u"   , l_cdb_stat.wlatcy);
    cdb_stat(s_cdb[CDB_GROUP_LOCAL_HIST], &l_cdb_stat);
    log_it(L_INFO, "Database \"%s\" opened"         , l_cdb_path);
    log_it(L_INFO, "Records: %-24u"                 , l_cdb_stat.rnum);
    log_it(L_INFO, "Average read latency: %-24u"    , l_cdb_stat.rlatcy);
    log_it(L_INFO, "Average write latency: %-24u"   , l_cdb_stat.wlatcy);
    cdb_stat(s_cdb[CDB_GROUP_LOCAL_LAST_TS], &l_cdb_stat);
    log_it(L_INFO, "Database \"%s\" opened"         , l_cdb_path);
    log_it(L_INFO, "Records: %-24u"                 , l_cdb_stat.rnum);
    log_it(L_INFO, "Average read latency: %-24u"    , l_cdb_stat.rlatcy);
    log_it(L_INFO, "Average write latency: %-24u"   , l_cdb_stat.wlatcy);
    DAP_DELETE(l_cdb_path);

    a_drv_callback->read_last_store_obj = dap_db_driver_cdb_read_last_store_obj;
    a_drv_callback->apply_store_obj     = dap_db_driver_cdb_apply_store_obj;
    a_drv_callback->read_store_obj      = dap_db_driver_cdb_read_store_obj;
    a_drv_callback->read_cond_store_obj = dap_db_driver_cdb_read_cond_store_obj;
    a_drv_callback->deinit              = dap_db_driver_cdb_deinit;

    return CDB_SUCCESS;
ERR:
    cdb_destroy(s_cdb[0]);
    cdb_destroy(s_cdb[1]);
    cdb_destroy(s_cdb[2]);
    DAP_DELETE(l_cdb_path);
    DAP_DELETE(s_cdb);
    return ret;
}

int dap_db_driver_cdb_deinit() {
    cdb_destroy(s_cdb[0]);
    cdb_destroy(s_cdb[1]);
    cdb_destroy(s_cdb[2]);
    DAP_DELETE(s_cdb);
    return CDB_SUCCESS;
}

dap_store_obj_t *dap_db_driver_cdb_read_last_store_obj(const char* a_group) {
    if (!a_group) return NULL;
    CDB_group l_group = dap_db_cdb_define_group(a_group);
    CDBSTAT l_cdb_stat;
    cdb_stat(s_cdb[l_group], &l_cdb_stat);
    void *l_iter = cdb_iterate_new(s_cdb[l_group], l_cdb_stat.rnum);
    obj_arg l_arg;
    l_arg.o = DAP_NEW_Z(dap_store_obj_t);
    l_arg.q = l_cdb_stat.rnum;
    cdb_iterate(s_cdb[l_group], dap_cdb_get_last_obj_iter_callback2, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(s_cdb[l_group], l_iter);
    l_arg.o->group = dap_strdup(a_group);
    return l_arg.o;
}

dap_store_obj_t *dap_db_driver_cdb_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out) {
    if (!a_group) {
        return NULL;
    }
    CDB_group l_group = dap_db_cdb_define_group(a_group);
    dap_store_obj_t *l_obj = NULL;
    if (a_key) {
        char *l_value;
        int l_vsize;
        cdb_get(s_cdb[l_group], a_key, strlen(a_key), (void**)&l_value, &l_vsize);
        if (!l_value) {
            return NULL;
        }
        l_obj = DAP_NEW_Z(dap_store_obj_t);
        cdb_serialize_val_to_dap_store_obj2(l_obj, a_key, l_value);
        l_obj->group = dap_strdup(a_group);
        cdb_free_val((void**)&l_value);
    } else {
        uint64_t l_count_out = 0;
        if(a_count_out) {
            l_count_out = *a_count_out;
        }
        CDBSTAT l_cdb_stat;
        cdb_stat(s_cdb[l_group], &l_cdb_stat);
        if ((l_count_out == 0) || (l_count_out > l_cdb_stat.rnum)) {
            l_count_out = l_cdb_stat.rnum;
        }
        obj_arg l_arg;
        l_arg.o = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count_out * sizeof(dap_store_obj_t));
        l_arg.q = l_count_out;
        l_arg.n = l_count_out;
        void *l_iter = cdb_iterate_new(s_cdb[l_group], 0);
        l_count_out = cdb_iterate(s_cdb[l_group], dap_cdb_get_some_obj_iter_callback, (void*)&l_arg, l_iter);
        cdb_iterate_destroy(s_cdb[l_group], l_iter);
        if(a_count_out) {
            *a_count_out = l_count_out;
        }
        for (ulong i = 0; i < l_count_out; ++i) {
            l_arg.o[i].group = dap_strdup(a_group);
        }
        l_obj = l_arg.o;
    }
    return l_obj;
}

dap_store_obj_t* dap_db_driver_cdb_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out) {
    if (!a_group) {
        return NULL;
    }
    CDB_group l_group = dap_db_cdb_define_group(a_group);
    dap_store_obj_t *l_obj = NULL;
    uint64_t l_count_out = 0;
    if(a_count_out) {
        l_count_out = *a_count_out;
    }
    CDBSTAT l_cdb_stat;
    cdb_stat(s_cdb[l_group], &l_cdb_stat);
    if ((l_count_out == 0) || (l_count_out > l_cdb_stat.rnum)) {
        l_count_out = l_cdb_stat.rnum;
    }
    obj_arg l_arg;
    l_arg.o = DAP_NEW_Z_SIZE(dap_store_obj_t, l_count_out * sizeof(dap_store_obj_t));
    l_arg.q = l_count_out;
    l_arg.q = l_count_out;
    void *l_iter = cdb_iterate_new(s_cdb[l_group], a_id + 1); // wrong! TODO: make use of obj->id
    l_count_out = cdb_iterate(s_cdb[l_group], dap_cdb_get_some_obj_iter_callback, (void*)&l_arg, l_iter);
    cdb_iterate_destroy(s_cdb[l_group], l_iter);
    if(a_count_out) {
        *a_count_out = l_count_out;
    }
    for (ulong i = 0; i < l_count_out; ++i) {
        l_arg.o[i].group = dap_strdup(a_group);
    }
    l_obj = l_arg.o;
}

int dap_db_driver_cdb_apply_store_obj(pdap_store_obj_t a_store_obj) {
    if(!a_store_obj || !a_store_obj->group) {
        return -1;
    }
    CDB_group l_group = dap_db_cdb_define_group(a_store_obj->group);
    if(a_store_obj->type == 'a') {
        if(!a_store_obj->key || !a_store_obj->value || !a_store_obj->value_len) return -2;
        cdb_record l_rec;
        l_rec.key = dap_strdup(a_store_obj->key);
        int offset = 0;
        char *l_val = DAP_NEW_Z_SIZE(char, uint64_size + sizeof(unsigned long) + a_store_obj->value_len + sizeof(time_t));
        dap_cdb_uint_to_hex(l_val, a_store_obj->id, uint64_size);
        offset += uint64_size;

        dap_cdb_uint_to_hex(l_val + offset, a_store_obj->value_len, sizeof(unsigned long));
        offset += sizeof(unsigned long);

        memcpy(l_val + offset, a_store_obj->value, a_store_obj->value_len);
        offset += a_store_obj->value_len;

        unsigned long l_time = (unsigned long)a_store_obj->timestamp;
        dap_cdb_uint_to_hex(l_val + offset, l_time, sizeof(time_t));
        offset += sizeof(time_t);
        l_rec.val = l_val;
        cdb_set(s_cdb[l_group], l_rec.key, strlen(l_rec.key), l_rec.val, offset);
    } else if(a_store_obj->type == 'd') {
        if(a_store_obj->key) {
            cdb_del(s_cdb[l_group], a_store_obj->key, strlen(a_store_obj->key));
        } else {
            cdb_close(s_cdb[l_group]); // TODO: re-open a cdb the appropriate path using the TRUNCATE arg
        }
    }
    return 0;
}
