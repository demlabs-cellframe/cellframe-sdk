/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stddef.h>
#include <string.h>
#include <pthread.h>

#ifdef DAP_OS_UNIX
#include <unistd.h>
#endif
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"
#include "dap_chain_global_db_driver_sqlite.h"

#define LOG_TAG "db_sqlite"

static sqlite3 *s_db = NULL;
static char *s_filename_db = NULL;
static pthread_rwlock_t s_db_rwlock = PTHREAD_RWLOCK_INITIALIZER;
// Value of one field in the table
typedef struct _SQLITE_VALUE_
{
    int32_t len;
    char type;
    /*
     #define SQLITE_INTEGER  1
     #define SQLITE_FLOAT    2
     #define SQLITE_TEXT     3
     #define SQLITE_BLOB     4
     #define SQLITE_NULL     5
     */
    uint8_t reserv[3];
    union
    {
        int val_int;
        long long val_int64;
        double val_float;
        const char *val_str;
        const unsigned char *val_blob;
    } val;
} SQLITE_VALUE;

// Content of one row in the table
typedef struct _SQLITE_ROW_VALUE_
{
    int count; // number of columns in a row
    int reserv;
    SQLITE_VALUE *val; // array of field values
} SQLITE_ROW_VALUE;

static int dap_db_driver_sqlite_exec(sqlite3 *l_db, const char *l_query, char **l_error_message);

/**
 * SQLite library initialization, no thread safe
 *
 * return 0 if Ok, else error code >0
 */
int dap_db_driver_sqlite_init(const char *a_filename_db, dap_db_driver_callbacks_t *a_drv_callback)
{
    int l_ret = -1;
    if(sqlite3_threadsafe() && !sqlite3_config(SQLITE_CONFIG_SERIALIZED))
        l_ret = sqlite3_initialize();
    if(l_ret != SQLITE_OK) {
        log_it(L_ERROR, "Can't init sqlite err=%d (%s)", l_ret, sqlite3_errstr(l_ret));
        return -2;
    }
    char *l_error_message = NULL;
    s_db = dap_db_driver_sqlite_open(a_filename_db, SQLITE_OPEN_READWRITE, &l_error_message);
    if(!s_db) {
        log_it(L_ERROR, "Can't init sqlite err: \"%s\"", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
        l_ret = -3;
    }
    else {
        if(!dap_db_driver_sqlite_set_pragma(s_db, "synchronous", "NORMAL")) // 0 | OFF | 1 | NORMAL | 2 | FULL
            printf("can't set new synchronous mode\n");
        if(!dap_db_driver_sqlite_set_pragma(s_db, "journal_mode", "OFF")) // DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
            printf("can't set new journal mode\n");

        if(!dap_db_driver_sqlite_set_pragma(s_db, "page_size", "1024")) // DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
            printf("can't set page_size\n");
        //      *PRAGMA page_size = bytes; // page size DB; it is reasonable to make it equal to the size of the disk cluster 4096
        //     *PRAGMA cache_size = -kibibytes; // by default it is equal to 2000 pages of database
//
        a_drv_callback->apply_store_obj = dap_db_driver_sqlite_apply_store_obj;
        a_drv_callback->read_store_obj = dap_db_driver_sqlite_read_store_obj;
        a_drv_callback->read_cond_store_obj = dap_db_driver_sqlite_read_cond_store_obj;
        a_drv_callback->read_last_store_obj = dap_db_driver_sqlite_read_last_store_obj;
        a_drv_callback->transaction_start = dap_db_driver_sqlite_start_transaction;
        a_drv_callback->transaction_end = dap_db_driver_sqlite_end_transaction;
        a_drv_callback->deinit = dap_db_driver_sqlite_deinit;
        a_drv_callback->flush = dap_db_driver_sqlite_flush;
        s_filename_db = strdup(a_filename_db);
    }
    return l_ret;
}

int dap_db_driver_sqlite_deinit(void)
{
        pthread_rwlock_wrlock(&s_db_rwlock);
        if(!s_db){
            pthread_rwlock_unlock(&s_db_rwlock);
            return -666;
        }
        dap_db_driver_sqlite_close(s_db);
        pthread_rwlock_unlock(&s_db_rwlock);
        s_db = NULL;
        return sqlite3_shutdown();
}

// additional function for sqlite to convert byte to number
static void byte_to_bin(sqlite3_context *l_context, int a_argc, sqlite3_value **a_argv)
{
    const unsigned char *l_text;
    if(a_argc != 1)
        sqlite3_result_null(l_context);
    l_text = (const unsigned char *) sqlite3_value_blob(a_argv[0]);
    if(l_text && l_text[0])
            {
        int l_result = (int) l_text[0];
        sqlite3_result_int(l_context, l_result);
        return;
    }
    sqlite3_result_null(l_context);
}

/**
 * Open SQLite database
 * a_filename_utf8 - database file name
 * a_flags - database access flags (SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
 * a_error_message[out] - Error messages (the memory requires deletion via sqlite_free ())
 *
 * return: database identifier, NULL when an error occurs.
 */
sqlite3* dap_db_driver_sqlite_open(const char *a_filename_utf8, int a_flags, char **a_error_message)
{
    sqlite3 *l_db = NULL;

    int l_rc = sqlite3_open_v2(a_filename_utf8, &l_db, a_flags | SQLITE_OPEN_NOMUTEX, NULL);
    // if unable to open the database file
    if(l_rc == SQLITE_CANTOPEN) {
        log_it(L_WARNING,"No database on path %s, creating one from scratch", a_filename_utf8);
        if(l_db)
            sqlite3_close(l_db);
        // try to create database
        l_rc = sqlite3_open_v2(a_filename_utf8, &l_db, a_flags | SQLITE_OPEN_NOMUTEX| SQLITE_OPEN_CREATE, NULL);
    }

    if(l_rc != SQLITE_OK) {
        log_it(L_CRITICAL,"Can't open database on path %s (code %d: \"%s\" )", a_filename_utf8, l_rc, sqlite3_errstr(l_rc));
        if(a_error_message)
            *a_error_message = sqlite3_mprintf("Can't open database: %s\n", sqlite3_errmsg(l_db));
        sqlite3_close(l_db);
        return NULL;
    }
    // added user functions
    sqlite3_create_function(l_db, "byte_to_bin", 1, SQLITE_UTF8, NULL, &byte_to_bin, NULL, NULL);
    return l_db;
}

/**
 * Close the database
 */
void dap_db_driver_sqlite_close(sqlite3 *l_db)
{
    if(l_db)
        sqlite3_close(l_db);
}
/*
 * Clear the memory allocated via sqlite3_mprintf()
 */
void dap_db_driver_sqlite_free(char *memory)
{
    if(memory)
        sqlite3_free(memory);
}

/**
 * Set specific pragma statements
 * www.sqlite.org/pragma.html
 *
 *PRAGMA page_size = bytes; // page size DB; it is reasonable to make it equal to the size of the disk cluster 4096
 *PRAGMA cache_size = -kibibytes; // by default it is equal to 2000 pages of database
 *PRAGMA encoding = "UTF-8";  // default = UTF-8
 *PRAGMA foreign_keys = 1; // default = 0
 *PRAGMA journal_mode = DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF;
 *PRAGMA synchronous = 0 | OFF | 1 | NORMAL | 2 | FULL;
 */
bool dap_db_driver_sqlite_set_pragma(sqlite3 *a_db, char *a_param, char *a_mode)
{
    if(!a_param || !a_mode)
            {
        printf("[sqlite_set_pragma] err!!! no param or mode\n");
        return false;
    }
    char *l_str_query = sqlite3_mprintf("PRAGMA %s = %s", a_param, a_mode);
    int l_rc = dap_db_driver_sqlite_exec(a_db, l_str_query, NULL); // default synchronous=FULL
    sqlite3_free(l_str_query);
    if(l_rc == SQLITE_OK)
        return true;
    return false;
}

int dap_db_driver_sqlite_flush()
{
    log_it(L_DEBUG, "Start flush sqlite data base.");
    pthread_rwlock_wrlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return -666;
    }
    dap_db_driver_sqlite_close(s_db);
    char *l_error_message;
    s_db = dap_db_driver_sqlite_open(s_filename_db, SQLITE_OPEN_READWRITE, &l_error_message);
    if(!s_db) {
        pthread_rwlock_unlock(&s_db_rwlock);
        log_it(L_ERROR, "Can't init sqlite err: \"%s\"", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
        return -3;
    }
#ifndef _WIN32
    sync();
#endif
    if(!dap_db_driver_sqlite_set_pragma(s_db, "synchronous", "NORMAL")) // 0 | OFF | 1 | NORMAL | 2 | FULL
        log_it(L_WARNING, "Can't set new synchronous mode\n");
    if(!dap_db_driver_sqlite_set_pragma(s_db, "journal_mode", "OFF")) // DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        log_it(L_WARNING, "Can't set new journal mode\n");

    if(!dap_db_driver_sqlite_set_pragma(s_db, "page_size", "1024")) // DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        log_it(L_WARNING, "Can't set page_size\n");
    pthread_rwlock_unlock(&s_db_rwlock);
    return 0;
}

/**
 * Execute SQL query to database that does not return data
 *
 * return 0 if Ok, else error code >0
 */
static int dap_db_driver_sqlite_exec(sqlite3 *l_db, const char *l_query, char **l_error_message)
{
    char *l_zErrMsg = NULL;
    int l_rc = sqlite3_exec(l_db, l_query, NULL, 0, &l_zErrMsg);
    //printf("%s\n",l_query);
    if(l_rc != SQLITE_OK)
    {
        if(l_error_message && l_zErrMsg)
            *l_error_message = sqlite3_mprintf("SQL error: %s", l_zErrMsg);
        if(l_zErrMsg)
            sqlite3_free(l_zErrMsg);
        return l_rc;
    }
    if(l_zErrMsg)
        sqlite3_free(l_zErrMsg);
    return l_rc;
}

/**
 * Create table
 *
 * return 0 if Ok, else error code
 */
static int dap_db_driver_sqlite_create_group_table(const char *a_table_name)
{
    char *l_error_message = NULL;
    if(!s_db || !a_table_name)
        return -1;
    char *l_query =
            dap_strdup_printf(
                    "create table if not exists '%s'(id INTEGER NOT NULL PRIMARY KEY, key TEXT KEY, hash BLOB, ts INTEGER KEY, value BLOB)",
                    a_table_name);
    if(dap_db_driver_sqlite_exec(s_db, (const char*) l_query, &l_error_message) != SQLITE_OK)
    {
        log_it(L_ERROR, "Creatу_table : %s\n", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
        DAP_DELETE(l_query);
        return -1;
    }
    DAP_DELETE(l_query);
    // create unique index - key
    l_query = dap_strdup_printf("create unique index if not exists 'idx_key_%s' ON '%s' (key)", a_table_name,
            a_table_name);
    if(dap_db_driver_sqlite_exec(s_db, (const char*) l_query, &l_error_message) != SQLITE_OK) {
        log_it(L_ERROR, "Create unique index : %s\n", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
        DAP_DELETE(l_query);
        return -1;
    }
    DAP_DELETE(l_query);
    return 0;
}

/**
 * Prepare SQL query for database
 * l_query [in] SQL-string with a query to database, example:
 * SELECT * FROM data
 * SELECT id, sd FROM data LIMIT 300
 * SELECT id, sd FROM data ORDER BY id ASC/DESC
 * SELECT * FROM data WHERE time>449464766900000 and time<449464766910000"
 * SELECT * FROM data WHERE hex(sd) LIKE '%370%'
 * hex(x'0806') -> '08f6' или quote(sd) -> X'08f6'
 * substr(x'031407301210361320690000',3,2) -> x'0730'
 *
 * CAST(substr(sd,5,2) as TEXT)
 * additional function of line to number _uint8
 * byte_to_bin(x'ff') -> 255
 */
static int dap_db_driver_sqlite_query(sqlite3 *db, char *query, sqlite3_stmt **l_res, char **l_error_message)
{
    const char *pzTail; // OUT: Pointer to unused portion of zSql
    int l_rc = sqlite3_prepare_v2(db, query, -1, l_res, &pzTail);
    if(l_rc != SQLITE_OK)
    {
        if(l_error_message)
        {
            const char *zErrMsg = sqlite3_errmsg(db);
            if(zErrMsg)
                *l_error_message = sqlite3_mprintf("SQL Query error: %s\n", zErrMsg);
        }
        return l_rc;
    }
    return l_rc;
}

/**
 * Clear memory after fetching a string
 *
 * return 0 if Ok, else -1
 */
static void dap_db_driver_sqlite_row_free(SQLITE_ROW_VALUE *row)
{
    if(row) {
        // delete the whole string
        sqlite3_free(row->val);
        // delete structure
        sqlite3_free(row);
    }
}

/**
 * Selects the next entry from the result of the query and returns an array
 *
 * l_res: identifier received in sqlite_query ()
 * l_row_out [out]: pointer to a column or NULL
 *
 * return:
 * SQLITE_ROW(100) has another row ready
 * SQLITE_DONE(101) finished executing,
 * SQLITE_CONSTRAINT(19) data is not unique and will not be added
 */
static int dap_db_driver_sqlite_fetch_array(sqlite3_stmt *l_res, SQLITE_ROW_VALUE **l_row_out)
{
    SQLITE_ROW_VALUE *l_row = NULL;
    // go to next the string
    int l_rc = sqlite3_step(l_res);
    if(l_rc == SQLITE_ROW) // SQLITE_ROW(100) or SQLITE_DONE(101) or SQLITE_BUSY(5)
    {
        int l_iCol; // number of the column in the row
        // allocate memory for a row with data
        l_row = (SQLITE_ROW_VALUE*) sqlite3_malloc(sizeof(SQLITE_ROW_VALUE));
        int l_count = sqlite3_column_count(l_res); // get the number of columns
        // allocate memory for all columns
        l_row->val = (SQLITE_VALUE*) sqlite3_malloc(l_count * (int)sizeof(SQLITE_VALUE));
        if(l_row->val)
        {
            l_row->count = l_count; // number of columns
            for(l_iCol = 0; l_iCol < l_row->count; l_iCol++)
                    {
                SQLITE_VALUE *cur_val = l_row->val + l_iCol;
                cur_val->len = sqlite3_column_bytes(l_res, l_iCol); // how many bytes will be needed
                cur_val->type = (signed char)sqlite3_column_type(l_res, l_iCol); // field type
                if(cur_val->type == SQLITE_INTEGER)
                {
                    cur_val->val.val_int64 = sqlite3_column_int64(l_res, l_iCol);
                    cur_val->val.val_int = sqlite3_column_int(l_res, l_iCol);
                }
                else if(cur_val->type == SQLITE_FLOAT)
                    cur_val->val.val_float = sqlite3_column_double(l_res, l_iCol);
                else if(cur_val->type == SQLITE_BLOB)
                    cur_val->val.val_blob = (const unsigned char*) sqlite3_column_blob(l_res, l_iCol);
                else if(cur_val->type == SQLITE_TEXT)
                    cur_val->val.val_str = (const char*) sqlite3_column_text(l_res, l_iCol); //sqlite3_mprintf("%s",sqlite3_column_text(l_res,iCol));
                else
                    cur_val->val.val_str = NULL;
            }
        }
        else
            l_row->count = 0; // number of columns
    }
    if(l_row_out)
        *l_row_out = l_row;
    else
        dap_db_driver_sqlite_row_free(l_row);
    return l_rc;
}

/**
 * Clear memory when request processing is complete
 */
static bool dap_db_driver_sqlite_query_free(sqlite3_stmt *l_res)
{
    if(!l_res)
        return false;
    int rc = sqlite3_finalize(l_res);
    if(rc != SQLITE_OK)
        return false;
    return true;
}

/**
 * Convert the array into a string to save to blob
 */
static char* dap_db_driver_get_string_from_blob(uint8_t *blob, int len)
{
    char *str_out;
    int ret;
    if(!blob)
        return NULL;
    str_out = (char*) sqlite3_malloc(len * 2 + 1);
    ret = (int)dap_bin2hex(str_out, (const void*)blob, (size_t)len);
    str_out[len * 2] = 0;
    return str_out;

}

/**
 * Cleaning the database from the deleted data
 *
 * return 0 if Ok, else error code >0
 */
int dap_db_driver_sqlite_vacuum(sqlite3 *l_db)
{
    if(!s_db)
        return -1;
    int l_rc = dap_db_driver_sqlite_exec(l_db, "VACUUM", NULL);
    return l_rc;
}

/**
 * Start a transaction
 */
int dap_db_driver_sqlite_start_transaction(void)
{
    pthread_rwlock_wrlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return -666;
    }

    if(SQLITE_OK == dap_db_driver_sqlite_exec(s_db, "BEGIN", NULL)){
        pthread_rwlock_unlock(&s_db_rwlock);
        return 0;
    }else{
        pthread_rwlock_unlock(&s_db_rwlock);
        return -1;
    }
}

/**
 * End of transaction
 */
int dap_db_driver_sqlite_end_transaction(void)
{
    pthread_rwlock_wrlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return -666;
    }
    if(SQLITE_OK == dap_db_driver_sqlite_exec(s_db, "COMMIT", NULL)){
        pthread_rwlock_unlock(&s_db_rwlock);
        return 0;
    }else{
        pthread_rwlock_unlock(&s_db_rwlock);
        return -1;
    }
}

char *dap_db_driver_sqlite_make_table_name(const char *a_group_name)
{
    char *l_group_name = dap_strdup(a_group_name);
    ssize_t l_group_name_len = (ssize_t)dap_strlen(l_group_name);
    const char *l_needle = ".";
    // replace '.' to '_'
    while(1){
    char *l_str = dap_strstr_len(l_group_name, l_group_name_len, l_needle);
    if(l_str)
        *l_str = '_';
    else
        break;
    }
    return l_group_name;
}

/**
 * Apply data (write or delete)
 *
 */
int dap_db_driver_sqlite_apply_store_obj(dap_store_obj_t *a_store_obj)
{
    if(!a_store_obj || !a_store_obj->group )
        return -1;
    char *l_query = NULL;
    char *l_error_message = NULL;
    if(a_store_obj->type == 'a') {
        if(!a_store_obj->key || !a_store_obj->value || !a_store_obj->value_len)
            return -1;
        //dap_chain_hash_fast_t l_hash;
        //dap_hash_fast(a_store_obj->value, a_store_obj->value_len, &l_hash);

        char *l_blob_hash = "";//dap_db_driver_get_string_from_blob((uint8_t*) &l_hash, sizeof(dap_chain_hash_fast_t));
        char *l_blob_value = dap_db_driver_get_string_from_blob(a_store_obj->value, (int)a_store_obj->value_len);
        //add one record
        char *table_name = dap_db_driver_sqlite_make_table_name(a_store_obj->group);
        l_query = sqlite3_mprintf("insert into '%s' values(NULL, '%s', x'%s', '%lld', x'%s')",
                table_name, a_store_obj->key, l_blob_hash, a_store_obj->timestamp, l_blob_value);
        DAP_DELETE(table_name);
        //dap_db_driver_sqlite_free(l_blob_hash);
        dap_db_driver_sqlite_free(l_blob_value);
    }
    else if(a_store_obj->type == 'd') {
        //delete one record
        if(a_store_obj->key)
            l_query = sqlite3_mprintf("delete from '%s' where key = '%s'",
                    a_store_obj->group, a_store_obj->key);
        // remove all group
        else{
            char * l_table_name = dap_db_driver_sqlite_make_table_name(a_store_obj->group);
            l_query = sqlite3_mprintf("drop table if exists '%s'", l_table_name);
            DAP_DELETE(l_table_name);
        }
    }
    else {
        log_it(L_ERROR, "Unknown store_obj type '0x%x'", a_store_obj->type);
        return -1;
    }
    // execute request
    pthread_rwlock_wrlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return -666;
    }

    int l_ret = dap_db_driver_sqlite_exec(s_db, l_query, &l_error_message);
    if(l_ret == SQLITE_ERROR) {
        dap_db_driver_sqlite_free(l_error_message);
        l_error_message = NULL;
        // create table
        char *table_name = dap_db_driver_sqlite_make_table_name(a_store_obj->group);
        dap_db_driver_sqlite_create_group_table(table_name);
        DAP_DELETE(table_name);
        // repeat request
        l_ret = dap_db_driver_sqlite_exec(s_db, l_query, &l_error_message);

    }
    // entry with the same hash is already present
    if(l_ret == SQLITE_CONSTRAINT) {
        dap_db_driver_sqlite_free(l_error_message);
        l_error_message = NULL;
        char *table_name = dap_db_driver_sqlite_make_table_name(a_store_obj->group);
        //delete exist record
        char *l_query_del = sqlite3_mprintf("delete from '%s' where key = '%s'", table_name, a_store_obj->key);
        l_ret = dap_db_driver_sqlite_exec(s_db, l_query_del, &l_error_message);
        DAP_DELETE(table_name);
        dap_db_driver_sqlite_free(l_query_del);
        if(l_ret != SQLITE_OK) {
            log_it(L_INFO, "Entry with the same key is already present and can't delete, %s", l_error_message);
            dap_db_driver_sqlite_free(l_error_message);
            l_error_message = NULL;
        }
        // repeat request
        l_ret = dap_db_driver_sqlite_exec(s_db, l_query, &l_error_message);
    }
    pthread_rwlock_unlock(&s_db_rwlock);
    // missing database
    if(l_ret != SQLITE_OK) {
        log_it(L_ERROR, "sqlite apply error: %s", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
        l_ret = -1;
    }
    dap_db_driver_sqlite_free(l_query);
    return l_ret;
}

static void fill_one_item(const char *a_group, dap_store_obj_t *a_obj, SQLITE_ROW_VALUE *a_row)
{
    a_obj->group = dap_strdup(a_group);

    for(int l_iCol = 0; l_iCol < a_row->count; l_iCol++) {
        SQLITE_VALUE *l_cur_val = a_row->val + l_iCol;
        switch (l_iCol) {
        case 0:
            if(l_cur_val->type == SQLITE_INTEGER)
                a_obj->id = (uint64_t)l_cur_val->val.val_int64;
            break; // id
        case 1:
            if(l_cur_val->type == SQLITE_INTEGER)
                a_obj->timestamp = l_cur_val->val.val_int64;
            break; // ts
        case 2:
            if(l_cur_val->type == SQLITE_TEXT)
                a_obj->key = dap_strdup(l_cur_val->val.val_str);
            break; // key
        case 3:
            if(l_cur_val->type == SQLITE_BLOB)
            {
                a_obj->value_len = (size_t) l_cur_val->len;
                a_obj->value = DAP_NEW_SIZE(uint8_t, a_obj->value_len);
                memcpy(a_obj->value, l_cur_val->val.val_blob, a_obj->value_len);
            }
            break; // value
        }
    }

}

/**
 * Read last items
 *
 * a_group - group name
 */
dap_store_obj_t* dap_db_driver_sqlite_read_last_store_obj(const char *a_group)
{

    dap_store_obj_t *l_obj = NULL;
    char *l_error_message = NULL;
    sqlite3_stmt *l_res;
    if(!a_group)
        return NULL;
    char * l_table_name = dap_db_driver_sqlite_make_table_name(a_group);
    char *l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' ORDER BY id DESC LIMIT 1", l_table_name);
    pthread_rwlock_rdlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return NULL;
    }

    int l_ret = dap_db_driver_sqlite_query(s_db, l_str_query, &l_res, &l_error_message);
    pthread_rwlock_unlock(&s_db_rwlock);
    sqlite3_free(l_str_query);
    DAP_DEL_Z(l_table_name);
    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "read last l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        dap_db_driver_sqlite_free(l_error_message);
        return NULL;
    }

    SQLITE_ROW_VALUE *l_row = NULL;
    l_ret = dap_db_driver_sqlite_fetch_array(l_res, &l_row);
    if(l_ret != SQLITE_ROW && l_ret != SQLITE_DONE)
    {
        //log_it(L_ERROR, "read l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
    }
    if(l_ret == SQLITE_ROW && l_row) {
        l_obj = DAP_NEW_Z(dap_store_obj_t);
        fill_one_item(a_group, l_obj, l_row);
    }
    dap_db_driver_sqlite_row_free(l_row);
    dap_db_driver_sqlite_query_free(l_res);

    return l_obj;
}

/**
 * Read several items with conditoin
 *
 * a_group - group name
 * a_id - read from this id
 * a_count_out[in], how many items to read, 0 - no limits
 * a_count_out[out], how many items was read
 */
dap_store_obj_t* dap_db_driver_sqlite_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out)
{
    dap_store_obj_t *l_obj = NULL;
    char *l_error_message = NULL;
    sqlite3_stmt *l_res;
    if(!a_group)
        return NULL;

    char * l_table_name = dap_db_driver_sqlite_make_table_name(a_group);
    // no limit
    int l_count_out = 0;
    if(a_count_out)
        l_count_out = (int)*a_count_out;
    char *l_str_query;
    if(l_count_out)
        l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE id>'%lld' ORDER BY id ASC LIMIT %d",
                l_table_name, a_id, l_count_out);
    else
        l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE id>'%lld' ORDER BY id ASC",
                l_table_name, a_id);
    pthread_rwlock_rdlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return NULL;
    }

    int l_ret = dap_db_driver_sqlite_query(s_db, l_str_query, &l_res, &l_error_message);
    pthread_rwlock_unlock(&s_db_rwlock);
    sqlite3_free(l_str_query);
    DAP_DEL_Z(l_table_name);

    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "read l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        dap_db_driver_sqlite_free(l_error_message);
        return NULL;
    }

    //int b = qlite3_column_count(s_db);
    SQLITE_ROW_VALUE *l_row = NULL;
    l_count_out = 0;
    int l_count_sized = 0;
    do {
        l_ret = dap_db_driver_sqlite_fetch_array(l_res, &l_row);
        if(l_ret != SQLITE_ROW && l_ret != SQLITE_DONE)
        {
           // log_it(L_ERROR, "read l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        }
        if(l_ret == SQLITE_ROW && l_row) {
            // realloc memory
            if(l_count_out >= l_count_sized) {
                l_count_sized += 10;
                l_obj = DAP_REALLOC(l_obj, sizeof(dap_store_obj_t) * (uint64_t)l_count_sized);
                memset(l_obj + l_count_out, 0, sizeof(dap_store_obj_t) * (uint64_t)(l_count_sized - l_count_out));
            }
            // fill current item
            dap_store_obj_t *l_obj_cur = l_obj + l_count_out;
            fill_one_item(a_group, l_obj_cur, l_row);
            l_count_out++;
        }
        dap_db_driver_sqlite_row_free(l_row);
    } while(l_row);

    dap_db_driver_sqlite_query_free(l_res);

    if(a_count_out)
        *a_count_out = (size_t)l_count_out;
    return l_obj;
}

/**
 * Read several items
 *
 * a_group - group name
 * a_key - key name, may by NULL, it means reading the whole group
 * a_count_out[in], how many items to read, 0 - no limits
 * a_count_out[out], how many items was read
 */
dap_store_obj_t* dap_db_driver_sqlite_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out)
{
    dap_store_obj_t *l_obj = NULL;
    char *l_error_message = NULL;
    sqlite3_stmt *l_res;
    if(!a_group)
        return NULL;

    char * l_table_name = dap_db_driver_sqlite_make_table_name(a_group);
    // no limit
    uint64_t l_count_out = 0;
    if(a_count_out)
        l_count_out = *a_count_out;
    char *l_str_query;
    if(a_key) {
        if(l_count_out)
            l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE key='%s' ORDER BY id ASC LIMIT %d",
                    l_table_name, a_key, l_count_out);
        else
            l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE key='%s' ORDER BY id ASC",
                    l_table_name, a_key);
    }
    else {
        if(l_count_out)
            l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' ORDER BY id ASC LIMIT %d",
                    l_table_name, l_count_out);
        else
            l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' ORDER BY id ASC", l_table_name);
    }
    pthread_rwlock_rdlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return NULL;
    }

    int l_ret = dap_db_driver_sqlite_query(s_db, l_str_query, &l_res, &l_error_message);
    pthread_rwlock_unlock(&s_db_rwlock);
    sqlite3_free(l_str_query);
    DAP_DEL_Z(l_table_name);
    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "read l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        dap_db_driver_sqlite_free(l_error_message);
        return NULL;
    }

    //int b = qlite3_column_count(s_db);
    SQLITE_ROW_VALUE *l_row = NULL;
    l_count_out = 0;
    uint64_t l_count_sized = 0;
    do {
        l_ret = dap_db_driver_sqlite_fetch_array(l_res, &l_row);
        if(l_ret != SQLITE_ROW && l_ret != SQLITE_DONE)
        {
           // log_it(L_ERROR, "read l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        }
        if(l_ret == SQLITE_ROW && l_row) {
            // realloc memory
            if(l_count_out >= l_count_sized) {
                l_count_sized += 10;
                l_obj = DAP_REALLOC(l_obj, sizeof(dap_store_obj_t) * l_count_sized);
                memset(l_obj + l_count_out, 0, sizeof(dap_store_obj_t) * (l_count_sized - l_count_out));
            }
            // fill currrent item
            dap_store_obj_t *l_obj_cur = l_obj + l_count_out;
            fill_one_item(a_group, l_obj_cur, l_row);
            l_count_out++;
        }
        dap_db_driver_sqlite_row_free(l_row);
    } while(l_row);

    dap_db_driver_sqlite_query_free(l_res);

    if(a_count_out)
        *a_count_out = l_count_out;
    return l_obj;
}
