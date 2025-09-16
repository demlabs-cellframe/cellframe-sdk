/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
        08-MAY-2022 RRL Added <ctx> field to the DB Driver interface table is called as <dap_global_db_driver_callbacks_t>;
                        a set of limits - see DAP$K/SZ constant definitions;
                        added lengths for the character fields.
 */

#pragma once

#include "dap_time.h"
#include "dap_list.h"
#include "dap_sign.h"
#include "dap_guuid.h"
#include "dap_stream_cluster.h"

#define DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX   128UL                               /* A maximum size of group name */
#define DAP_GLOBAL_DB_GROUPS_COUNT_MAX      1024UL                              /* A maximum number of groups */
#define DAP_GLOBAL_DB_KEY_SIZE_MAX          512UL                               /* A limit for the key's length in DB */

#define DAP_GLOBAL_DB_COND_READ_COUNT_DEFAULT 256UL                             /* Default count of records to return with conditional read */
#define DAP_GLOBAL_DB_COND_READ_KEYS_DEFAULT  512UL                             /* Default count of keys to return with conditional read */

// Main record flags (DB saved)
#define DAP_GLOBAL_DB_RECORD_DEL        BIT(0)                                  /* Information of record deletion (key, timestamp and sign) propagated over sync */
#define DAP_GLOBAL_DB_RECORD_PINNED     BIT(1)                                  /* Record can be removed only after clearing this flag */
// Auxiliary flags (not saved in DB)
#define DAP_GLOBAL_DB_RECORD_NEW        BIT(6)                                  /* Record is newly generated, and not appears by synchronizstion */
#define DAP_GLOBAL_DB_RECORD_ERASE      BIT(7)                                  /* Record will be definitevly erased w/o notifications or sync */

typedef struct dap_global_db_driver_hash {
    dap_nanotime_t bets;
    uint64_t becrc;
} DAP_ALIGN_PACKED dap_global_db_driver_hash_t;

typedef struct dap_store_obj {
    char *group;                    // Name of database table analogue (key-value DB have no 'table' defined)
    char *key;                      // Unique database key
    byte_t *value;                  // Database value corresponsing with database key
    size_t value_len;               // Length of database value
    uint8_t flags;                  // Record flags
    dap_sign_t *sign;               // Crypto sign for authentication and security checks
    dap_nanotime_t timestamp;       // Timestamp of record creation, in nanoseconds since EPOCH
    uint64_t crc;                   // Integrity control
    byte_t ext[];                   // For extra data transfer between sync callbacks
} dap_store_obj_t;

// Operation type - for event notifiers
typedef enum dap_global_db_optype {
    DAP_GLOBAL_DB_OPTYPE_ADD  = 0x61,    /* 'a', */                             /* Operation type INSERT / OVERWRITE */
    DAP_GLOBAL_DB_OPTYPE_DEL  = 0x64,    /* 'd', */                             /* Operation type DELETE */
} dap_global_db_optype_t;

DAP_STATIC_INLINE dap_global_db_optype_t dap_store_obj_get_type(dap_store_obj_t *a_obj)
{
    return a_obj->flags & DAP_GLOBAL_DB_RECORD_DEL ? DAP_GLOBAL_DB_OPTYPE_DEL : DAP_GLOBAL_DB_OPTYPE_ADD;
}

DAP_STATIC_INLINE dap_global_db_driver_hash_t dap_global_db_driver_hash_get(dap_store_obj_t *a_obj)
{
    dap_global_db_driver_hash_t l_ret = { .bets = htobe64(a_obj->timestamp), .becrc = htobe64(a_obj->crc) };
    return l_ret;
}

DAP_STATIC_INLINE int dap_global_db_driver_hash_compare(dap_global_db_driver_hash_t *a_hash1, dap_global_db_driver_hash_t *a_hash2)
{
    int l_ret = memcmp(a_hash1, a_hash2, sizeof(dap_global_db_driver_hash_t));
    return l_ret < 0 ? -1 : (l_ret > 0 ? 1 : 0);
}

DAP_STATIC_INLINE int dap_store_obj_driver_hash_compare(dap_store_obj_t *a_obj1, dap_store_obj_t *a_obj2)
{
    if (!a_obj1)
        return a_obj2 ? -1 : 0;
    if (!a_obj2)
        return 1;
    dap_global_db_driver_hash_t l_hash1 = dap_global_db_driver_hash_get(a_obj1),
                                l_hash2 = dap_global_db_driver_hash_get(a_obj2);
    return dap_global_db_driver_hash_compare(&l_hash1, &l_hash2);
}

DAP_STATIC_INLINE bool dap_store_obj_driver_obj_compare(dap_store_obj_t *a_obj1,  dap_store_obj_t *a_obj2)
{
    return dap_store_obj_driver_hash_compare(a_obj1, a_obj2) || a_obj1->flags != a_obj2->flags ||
        a_obj1->value_len != a_obj2->value_len || memcmp(a_obj1->value, a_obj2->value, a_obj1->value_len) ||
        dap_sign_get_size(a_obj1->sign) != dap_sign_get_size(a_obj2->sign) || memcmp(a_obj1->sign, a_obj2->sign, dap_sign_get_size(a_obj1->sign)) ||
        strcmp(a_obj1->key, a_obj2->key) || strcmp(a_obj1->group, a_obj2->group);
}


DAP_STATIC_INLINE const char *dap_global_db_driver_hash_print(dap_global_db_driver_hash_t a_hash)
{
    return dap_guuid_to_hex_str(dap_guuid_compose(a_hash.bets, a_hash.becrc));
}

extern const dap_global_db_driver_hash_t c_dap_global_db_driver_hash_blank;

DAP_STATIC_INLINE bool dap_global_db_driver_hash_is_blank(dap_global_db_driver_hash_t *a_blank_candidate)
{
    return !memcmp(a_blank_candidate, &c_dap_global_db_driver_hash_blank, sizeof(dap_global_db_driver_hash_t));
}

typedef struct dap_global_db_hash_pkt dap_global_db_hash_pkt_t;
typedef struct dap_global_db_pkt_pack dap_global_db_pkt_pack_t;

typedef int (*dap_global_db_driver_write_callback_t)(dap_store_obj_t *a_store_obj);
typedef dap_store_obj_t* (*dap_global_db_driver_read_callback_t)(const char *a_group, const char *a_key, size_t *a_count_out, bool a_with_holes);
typedef dap_store_obj_t* (*dap_global_db_driver_read_cond_callback_t)(const char *a_group, dap_global_db_driver_hash_t a_hash_from, size_t *a_count, bool a_with_holes);
typedef dap_global_db_hash_pkt_t * (*dap_global_db_driver_read_hashes_callback_t)(const char *a_group, dap_global_db_driver_hash_t a_hash_from);
typedef dap_store_obj_t* (*dap_global_db_driver_read_last_callback_t)(const char *a_group, bool a_with_holes);
typedef size_t (*dap_global_db_driver_read_count_callback_t)(const char *a_group, dap_global_db_driver_hash_t a_hash_from, bool a_with_holes);
typedef dap_list_t* (*dap_global_db_driver_get_groups_callback_t)(const char *a_mask);
typedef bool (*dap_global_db_driver_is_obj_callback_t)(const char *a_group, const char *a_key);
typedef bool (*dap_global_db_driver_is_hash_callback_t)(const char *a_group, dap_global_db_driver_hash_t a_hash);
typedef dap_global_db_pkt_pack_t * (*dap_global_db_driver_get_by_hash_callback_t)(const char *a_group, dap_global_db_driver_hash_t *a_hash, size_t a_count);
typedef int (*dap_global_db_driver_txn_start_callback_t)(void);
typedef int (*dap_global_db_driver_txn_end_callback_t)(bool);
typedef int (*dap_global_db_driver_callback_t)(void);

typedef struct dap_global_db_driver_callbacks {
    dap_global_db_driver_write_callback_t      apply_store_obj;                    /* Performs an DB's action like: INSERT/DELETE/UPDATE for the given
                                                                              'store object' */
    dap_global_db_driver_read_callback_t       read_store_obj;                     /* Retreive 'store object' from DB */
    dap_global_db_driver_read_last_callback_t  read_last_store_obj;
    dap_global_db_driver_read_cond_callback_t  read_cond_store_obj;
    dap_global_db_driver_read_hashes_callback_t read_hashes;
    dap_global_db_driver_read_count_callback_t read_count_store;

    dap_global_db_driver_get_groups_callback_t get_groups_by_mask;                 /* Return a list of tables/groups has been matched to pattern */

    dap_global_db_driver_is_obj_callback_t     is_obj;                             /* Check for existence of a record in the table/group for
                                                                              a given <key> */
    dap_global_db_driver_is_hash_callback_t    is_hash;                            /* Check for existence of a record in the table/group for
                                                                              a given driver hash */
    dap_global_db_driver_get_by_hash_callback_t get_by_hash;                       /* Retrieve a record from the table/group for a given driver hash */

    dap_global_db_driver_txn_start_callback_t  transaction_start;                  /* Allocate DB context for consequtive operations */
    dap_global_db_driver_txn_end_callback_t    transaction_end;                    /* Release DB context at end of DB consequtive operations */

    dap_global_db_driver_callback_t            deinit;
    dap_global_db_driver_callback_t            flush;
} dap_global_db_driver_callbacks_t;

int     dap_global_db_driver_init(const char *driver_name, const char *a_filename_db);
void    dap_global_db_driver_deinit(void);

dap_store_obj_t *dap_store_obj_copy(dap_store_obj_t *a_store_obj, size_t a_store_count);
dap_store_obj_t *dap_store_obj_copy_ext(dap_store_obj_t *a_store_obj, void *a_ext, size_t a_ext_size);
dap_store_obj_t *dap_global_db_store_objs_copy(dap_store_obj_t *, const dap_store_obj_t *, size_t);
void    dap_store_obj_free(dap_store_obj_t *a_store_obj, size_t a_store_count);
DAP_STATIC_INLINE void dap_store_obj_free_one(dap_store_obj_t *a_store_obj) { return dap_store_obj_free(a_store_obj, 1); }
int     dap_global_db_driver_flush(void);

int dap_global_db_driver_apply(dap_store_obj_t *a_store_obj, size_t a_store_count);
int dap_global_db_driver_add(dap_store_obj_t *a_store_obj, size_t a_store_count);
int dap_global_db_driver_delete(dap_store_obj_t * a_store_obj, size_t a_store_count);
dap_store_obj_t *dap_global_db_driver_read_last(const char *a_group, bool a_with_holes);
dap_store_obj_t *dap_global_db_driver_cond_read(const char *a_group, dap_global_db_driver_hash_t a_hash_from, size_t *a_count_out, bool a_with_holes);
dap_store_obj_t *dap_global_db_driver_read(const char *a_group, const char *a_key, size_t *count_out, bool a_with_holes);
dap_global_db_pkt_pack_t *dap_global_db_driver_get_by_hash(const char *a_group, dap_global_db_driver_hash_t *a_hashes, size_t a_count);
bool dap_global_db_driver_is(const char *a_group, const char *a_key);
bool dap_global_db_driver_is_hash(const char *a_group, dap_global_db_driver_hash_t a_hash);
size_t dap_global_db_driver_count(const char *a_group, dap_global_db_driver_hash_t a_hash_from, bool a_with_holes);
dap_list_t *dap_global_db_driver_get_groups_by_mask(const char *a_group_mask);
dap_global_db_hash_pkt_t *dap_global_db_driver_hashes_read(const char *a_group, dap_global_db_driver_hash_t a_hash_from);
int dap_global_db_driver_txn_start();
int dap_global_db_driver_txn_end(bool a_commit);
