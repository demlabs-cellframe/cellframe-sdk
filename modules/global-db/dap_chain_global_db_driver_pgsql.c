/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2021
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
#include <errno.h>
#include <pwd.h>

#ifdef DAP_OS_UNIX
#include <unistd.h>
#endif
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_chain_global_db_driver_pgsql.h"

#define LOG_TAG "db_pgsql"

struct dap_pgsql_conn_pool_item {
    PGconn *conn;
    int busy;
};

static struct dap_pgsql_conn_pool_item s_conn_pool[DAP_PGSQL_POOL_COUNT];
static pthread_rwlock_t s_db_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static PGconn *s_pgsql_get_connection(void)
{
    PGconn *l_ret = NULL;
    pthread_rwlock_rdlock(&s_db_rwlock);
    for (int i = 0; i < DAP_PGSQL_POOL_COUNT; i++) {
        if (!s_conn_pool[i].busy) {
            l_ret = s_conn_pool[i].conn;
            s_conn_pool[i].busy = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&s_db_rwlock);
    return l_ret;
}

static void s_pgsql_free_connection(PGconn *a_conn)
{
    pthread_rwlock_rdlock(&s_db_rwlock);
    for (int i = 0; i < DAP_PGSQL_POOL_COUNT; i++) {
        if (s_conn_pool[i].conn == a_conn) {
            s_conn_pool[i].busy = 0;
        }
    }
    pthread_rwlock_unlock(&s_db_rwlock);
}

/**
 * SQLite library initialization, no thread safe
 *
 * return 0 if Ok, else error code >0
 */
int dap_db_driver_pgsql_init(const char *a_filename_dir, dap_db_driver_callbacks_t *a_drv_callback)
{
    // Check paths and create them if nessesary
    if (!dap_dir_test(a_filename_dir)) {
        log_it(L_NOTICE, "No directory %s, trying to create...", a_filename_dir);
        int l_mkdir_ret = dap_mkdir_with_parents(a_filename_dir);
        int l_errno = errno;
        if (!dap_dir_test(a_filename_dir)) {
            char l_errbuf[255];
            l_errbuf[0] = '\0';
            strerror_r(l_errno, l_errbuf, sizeof(l_errbuf));
            log_it(L_ERROR, "Can't create directory, error code %d, error string \"%s\"", l_mkdir_ret, l_errbuf);
            return -1;
        } else
            log_it(L_NOTICE,"Directory created");
    }
    dap_hash_fast_t l_dir_hash;
    dap_hash_fast(a_filename_dir, strlen(a_filename_dir), &l_dir_hash);
    char l_db_name[DAP_PGSQL_DBHASHNAME_LEN + 1];
    dap_htoa64(l_db_name, l_dir_hash.raw, DAP_PGSQL_DBHASHNAME_LEN);
    l_db_name[DAP_PGSQL_DBHASHNAME_LEN] = '\0';
    // Open PostgreSQL database, create if nessesary
    const char *l_base_conn_str = "dbname = postgres";
    PGconn *l_base_conn = PQconnectdb(l_base_conn_str);
    if (PQstatus(l_base_conn) != CONNECTION_OK) {
        log_it(L_ERROR, "Can't init PostgreSQL database: \"%s\"", PQerrorMessage(l_base_conn));
        PQfinish(l_base_conn);
        return -2;
    }
    char *l_query_str = dap_strdup_printf("SELECT EXISTS (SELECT * FROM pg_database WHERE datname = '%s')", l_db_name);
    PGresult *l_res = PQexec(l_base_conn, l_query_str);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        log_it(L_ERROR, "Can't read PostgreSQL database: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        return -3;
    }
    if (*PQgetvalue(l_res, 0, 0) == 'f') {  //false, database not exists, than create it
        PQclear(l_res);
        l_query_str = dap_strdup_printf("DROP TABLESPACE IF EXISTS \"%s\"", l_db_name);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Drop tablespace failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            return -4;
        }
        PQclear(l_res);
        dap_mkdir_with_parents(a_filename_dir);
        chown(a_filename_dir, getpwnam("postgres")->pw_uid, -1);
        l_query_str = dap_strdup_printf("CREATE TABLESPACE \"%s\" LOCATION '%s'", l_db_name, a_filename_dir);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Create tablespace failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            return -5;
        }
        PQclear(l_res);
        l_query_str = dap_strdup_printf("CREATE DATABASE \"%s\" WITH TABLESPACE \"%s\"", l_db_name, l_db_name);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Create database failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            return -6;
        }
    }
    PQclear(l_res);
    PQfinish(l_base_conn);
    // Create connection pool for the DAP database
    char *l_conn_str = dap_strdup_printf("dbname = %s", l_db_name);
    for (int i = 0; i < DAP_PGSQL_POOL_COUNT; i++) {
        s_conn_pool[i].conn = PQconnectdb(l_conn_str);
        s_conn_pool[i].busy = 0;
        if (PQstatus(s_conn_pool[i].conn) != CONNECTION_OK) {
            log_it(L_ERROR, "Can't connect PostgreSQL database: \"%s\"", PQerrorMessage(s_conn_pool[i].conn));
            DAP_DELETE(l_conn_str);
            for (int j = 0; j <= i; j++)
                PQfinish(s_conn_pool[j].conn);
            return -7;
        }
    }
    DAP_DELETE(l_conn_str);
    pthread_rwlock_init(&s_db_rwlock, 0);
    a_drv_callback->transaction_start = dap_db_driver_pgsql_start_transaction;
    a_drv_callback->transaction_end = dap_db_driver_pgsql_end_transaction;
    a_drv_callback->apply_store_obj = dap_db_driver_pgsql_apply_store_obj;
    a_drv_callback->read_store_obj = dap_db_driver_pgsql_read_store_obj;
    //a_drv_callback->read_cond_store_obj = dap_db_driver_sqlite_read_cond_store_obj;
    //a_drv_callback->read_last_store_obj = dap_db_driver_sqlite_read_last_store_obj;
    //a_drv_callback->get_groups_by_mask  = dap_db_driver_sqlite_get_groups_by_mask;
    //a_drv_callback->read_count_store = dap_db_driver_sqlite_read_count_store;
    //a_drv_callback->is_obj = dap_db_driver_sqlite_is_obj;
    //a_drv_callback->deinit = dap_db_driver_sqlite_deinit;
    //a_drv_callback->flush = dap_db_driver_sqlite_flush;
    return 0;
}


int dap_db_driver_pgsql_deinit(void)
{
    pthread_rwlock_wrlock(&s_db_rwlock);
    for (int j = 0; j <= DAP_PGSQL_POOL_COUNT; j++)
        PQfinish(s_conn_pool[j].conn);
    pthread_rwlock_unlock(&s_db_rwlock);
    pthread_rwlock_destroy(&s_db_rwlock);
    return 0;
}

/**
 * Start a transaction
 */
int dap_db_driver_pgsql_start_transaction(void)
{
    // TODO make a transaction with a single connection from pool
    //PGresult *l_res = PQexec(l_conn, "BEGIN");
    return 0;
}

/**
 * End of transaction
 */
int dap_db_driver_pgsql_end_transaction(void)
{
    // TODO make a transaction with a single connection from pool
    //PGresult *l_res = PQexec(l_conn, "COMMIT");
    return 0;
}

/**
 * Create table
 *
 * return 0 if Ok, else error code
 */
static int s_pgsql_create_group_table(const char *a_table_name)
{
    if (!a_table_name)
        return -1;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return -2;
    }
    int l_ret = 0;
    char *l_query_str = dap_strdup_printf("CREATE TABLE \"%s\""
                                          "(obj_id SERIAL PRIMARY KEY, obj_ts BIGINT, obj_key TEXT UNIQUE, obj_val BYTEA)",
                                          a_table_name);
    PGresult *l_res = PQexec(l_conn, l_query_str);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
        log_it(L_ERROR, "Create table failed with message: \"%s\"", PQresultErrorMessage(l_res));
        l_ret = -3;
    }
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    return l_ret;
}

/**
 * Apply data (write or delete)
 *
 */
int dap_db_driver_pgsql_apply_store_obj(dap_store_obj_t *a_store_obj)
{
    if (!a_store_obj || !a_store_obj->group)
        return -1;
    char *l_query_str = NULL;
    int l_ret = 0;
    PGresult *l_res = NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return -2;
    }
    if (a_store_obj->type == 'a') {
        const char *l_param_vals[2];
        time_t l_ts_to_store = htobe64(a_store_obj->timestamp);
        l_param_vals[0] = (const char *)&l_ts_to_store;
        l_param_vals[1] = (const char *)a_store_obj->value;
        int l_param_lens[2] = {sizeof(time_t), a_store_obj->value_len};
        int l_param_formats[2] = {1, 1};
        l_query_str = dap_strdup_printf("INSERT INTO \"%s\" (obj_ts, obj_key, obj_val) VALUES ($1, '%s', $2) "
                                        "ON CONFLICT (obj_key) DO UPDATE SET "
                                        "obj_ts = EXCLUDED.obj_ts, obj_val = EXCLUDED.obj_val;",
                                        a_store_obj->group,  a_store_obj->key);

        // execute add request
        l_res = PQexecParams(l_conn, l_query_str, 2, NULL, l_param_vals, l_param_lens, l_param_formats, 0);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            if (a_store_obj->type == 'a' && s_pgsql_create_group_table(a_store_obj->group) == 0) {
                PQclear(l_res);
                l_res = PQexecParams(l_conn, l_query_str, 2, NULL, l_param_vals, l_param_lens, l_param_formats, 0);
            }
            if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
                log_it(L_ERROR, "Add object failed with message: \"%s\"", PQresultErrorMessage(l_res));
                l_ret = -3;
            }
        }
    } else if (a_store_obj->type == 'd') {
        // delete one record
        if (a_store_obj->key)
            l_query_str = dap_strdup_printf("DELETE FROM \"%s\" WHERE key = \"%s\"",
                                            a_store_obj->group, a_store_obj->key);
        // remove all group
        else
            l_query_str = dap_strdup_printf("DROP TABLE \"%s\"", a_store_obj->group);
        // execute delete request
        l_res = PQexec(l_conn, l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Delete object failed with message: \"%s\"", PQresultErrorMessage(l_res));
            l_ret = -4;
        }
    }
    else {
        log_it(L_ERROR, "Unknown store_obj type '0x%x'", a_store_obj->type);
        s_pgsql_free_connection(l_conn);
        return -5;
    }
    DAP_DELETE(l_query_str);
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    return l_ret;
}

static void s_pgsql_fill_object(const char *a_group, dap_store_obj_t *a_obj, PGresult *a_res, int a_row)
{
    a_obj->group = dap_strdup(a_group);

    for (int i = 0; i < PQnfields(a_res); i++) {
        if (i == PQfnumber(a_res, "obj_id")) {
            a_obj->id = be32toh(*(uint32_t *)PQgetvalue(a_res, a_row, i));
        } else if (i == PQfnumber(a_res, "obj_ts")) {
            a_obj->timestamp = be64toh(*(time_t *)PQgetvalue(a_res, a_row, i));
        } else if ((i == PQfnumber(a_res, "obj_key"))) {
            a_obj->key = dap_strdup(PQgetvalue(a_res, a_row, i));
        } else if ((i == PQfnumber(a_res, "obj_val"))) {
            a_obj->value_len = PQgetlength(a_res, a_row, i);
            a_obj->value = DAP_DUP_SIZE(PQgetvalue(a_res, a_row, i), a_obj->value_len);
        }
    }
}

/**
 * Read several items
 *
 * a_group - group name
 * a_key - key name, may by NULL, it means reading the whole group
 * a_count_out[in], how many items to read, 0 - no limits
 * a_count_out[out], how many items was read
 */
dap_store_obj_t *dap_db_driver_pgsql_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out)
{
    if (!a_group)
        return NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return NULL;
    }
    char *l_query_str;
    if (a_key) {
       l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" WHERE obj_key='%s'", a_group, a_key);
    } else {
        if (a_count_out)
            l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" ORDER BY obj_id ASC LIMIT %d", a_group, *a_count_out);
        else
            l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" ORDER BY obj_id ASC", a_group);
    }

    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        log_it(L_ERROR, "Read objects failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        return NULL;
    }

    // parse reply
    size_t l_count = PQntuples(l_res);
    dap_store_obj_t *l_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * l_count);
    for (int i = 0; i < l_count; i++) {
        // fill currrent item
        dap_store_obj_t *l_obj_cur = l_obj + i;
        s_pgsql_fill_object(a_group, l_obj_cur, l_res, i);
    }
    PQclear(l_res);
    if (a_count_out)
        *a_count_out = l_count;
    return l_obj;
}

#if 0
int dap_db_driver_sqlite_flush()
{
    log_it(L_DEBUG, "Start flush sqlite data base.");
    pthread_rwlock_wrlock(&s_db_rwlock);
    if(!s_db){
        pthread_rwlock_unlock(&s_db_rwlock);
        return -666;
    }
    dap_db_driver_sqlite_close(s_db);
    char *l_error_message = NULL;
    s_db = dap_db_driver_sqlite_open(s_filename_db, SQLITE_OPEN_READWRITE, &l_error_message);
    if(!s_db) {
        pthread_rwlock_unlock(&s_db_rwlock);
        log_it(L_ERROR, "Can't init sqlite err: \"%s\"", l_error_message? l_error_message: "UNKNOWN");
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
    pthread_rwlock_wrlock(&s_db_rwlock);
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
        l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE id>='%lld' ORDER BY id ASC LIMIT %d",
                l_table_name, a_id, l_count_out);
    else
        l_str_query = sqlite3_mprintf("SELECT id,ts,key,value FROM '%s' WHERE id>='%lld' ORDER BY id ASC",
                l_table_name, a_id);
    pthread_rwlock_wrlock(&s_db_rwlock);
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



dap_list_t* dap_db_driver_sqlite_get_groups_by_mask(const char *a_group_mask)
{
    if(!a_group_mask || !s_db)
        return NULL;
    sqlite3_stmt *l_res;
    const char *l_str_query = "SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%'";
    dap_list_t *l_ret_list = NULL;
    pthread_rwlock_wrlock(&s_db_rwlock);
    int l_ret = dap_db_driver_sqlite_query(s_db, (char *)l_str_query, &l_res, NULL);
    pthread_rwlock_unlock(&s_db_rwlock);
    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "Get tables l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        return NULL;
    }
    char * l_mask = dap_db_driver_sqlite_make_table_name(a_group_mask);
    SQLITE_ROW_VALUE *l_row = NULL;
    while (dap_db_driver_sqlite_fetch_array(l_res, &l_row) == SQLITE_ROW && l_row) {
        char *l_table_name = (char *)l_row->val->val.val_str;
        if(!dap_fnmatch(l_mask, l_table_name, 0))
            l_ret_list = dap_list_prepend(l_ret_list, dap_db_driver_sqlite_make_group_name(l_table_name));
        dap_db_driver_sqlite_row_free(l_row);
    }
    dap_db_driver_sqlite_query_free(l_res);
    return l_ret_list;
}

size_t dap_db_driver_sqlite_read_count_store(const char *a_group, uint64_t a_id)
{
    sqlite3_stmt *l_res;
    if(!a_group || ! s_db)
        return 0;

    char * l_table_name = dap_db_driver_sqlite_make_table_name(a_group);
    char *l_str_query = sqlite3_mprintf("SELECT COUNT(*) FROM '%s' WHERE id>='%lld'", l_table_name, a_id);
    pthread_rwlock_wrlock(&s_db_rwlock);
    int l_ret = dap_db_driver_sqlite_query(s_db, l_str_query, &l_res, NULL);
    pthread_rwlock_unlock(&s_db_rwlock);
    sqlite3_free(l_str_query);
    DAP_DEL_Z(l_table_name);

    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "Count l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        return 0;
    }
    size_t l_ret_val;
    SQLITE_ROW_VALUE *l_row = NULL;
    if (dap_db_driver_sqlite_fetch_array(l_res, &l_row) == SQLITE_ROW && l_row) {
        l_ret_val = (size_t)l_row->val->val.val_int64;
        dap_db_driver_sqlite_row_free(l_row);
    }
    dap_db_driver_sqlite_query_free(l_res);
    return l_ret_val;
}

bool dap_db_driver_sqlite_is_obj(const char *a_group, const char *a_key)
{
    sqlite3_stmt *l_res;
    if(!a_group || ! s_db)
        return false;

    char * l_table_name = dap_db_driver_sqlite_make_table_name(a_group);
    char *l_str_query = sqlite3_mprintf("SELECT EXISTS(SELECT * FROM '%s' WHERE key='%s')", l_table_name, a_key);
    pthread_rwlock_wrlock(&s_db_rwlock);
    int l_ret = dap_db_driver_sqlite_query(s_db, l_str_query, &l_res, NULL);
    pthread_rwlock_unlock(&s_db_rwlock);
    sqlite3_free(l_str_query);
    DAP_DEL_Z(l_table_name);

    if(l_ret != SQLITE_OK) {
        //log_it(L_ERROR, "Exists l_ret=%d, %s\n", sqlite3_errcode(s_db), sqlite3_errmsg(s_db));
        return false;
    }
    bool l_ret_val;
    SQLITE_ROW_VALUE *l_row = NULL;
    if (dap_db_driver_sqlite_fetch_array(l_res, &l_row) == SQLITE_ROW && l_row) {
        l_ret_val = (size_t)l_row->val->val.val_int64;
        dap_db_driver_sqlite_row_free(l_row);
    }
    dap_db_driver_sqlite_query_free(l_res);
    return l_ret_val;
}
#endif
