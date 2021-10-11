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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_chain_global_db_driver_pgsql.h"

#define LOG_TAG "db_pgsql"

#ifdef DAP_CHAIN_GDB_ENGINE_PGSQL
struct dap_pgsql_conn_pool_item {
    PGconn *conn;
    int busy;
};

static PGconn *s_trans_conn = NULL;
static struct dap_pgsql_conn_pool_item s_conn_pool[DAP_PGSQL_POOL_COUNT];
static pthread_rwlock_t s_db_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static PGconn *s_pgsql_get_connection(void)
{
    if (pthread_rwlock_wrlock(&s_db_rwlock) == EDEADLK) {
        return s_trans_conn;
    }
    PGconn *l_ret = NULL;
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
    if (pthread_rwlock_wrlock(&s_db_rwlock) == EDEADLK) {
        return;
    }
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
    dap_hash_fast_t l_dir_hash;
    dap_hash_fast(a_filename_dir, strlen(a_filename_dir), &l_dir_hash);
    char l_db_name[DAP_PGSQL_DBHASHNAME_LEN + 1];
    dap_htoa64(l_db_name, l_dir_hash.raw, DAP_PGSQL_DBHASHNAME_LEN);
    l_db_name[DAP_PGSQL_DBHASHNAME_LEN] = '\0';
    if (!dap_dir_test(a_filename_dir) || !readdir(opendir(a_filename_dir))) {
        // Create PostgreSQL database
        const char *l_base_conn_str = "dbname = postgres";
        PGconn *l_base_conn = PQconnectdb(l_base_conn_str);
        if (PQstatus(l_base_conn) != CONNECTION_OK) {
            log_it(L_ERROR, "Can't init PostgreSQL database: \"%s\"", PQerrorMessage(l_base_conn));
            PQfinish(l_base_conn);
            return -2;
        }
        char *l_query_str = dap_strdup_printf("DROP DATABASE IF EXISTS \"%s\"", l_db_name);
        PGresult *l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Drop database failed: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            PQfinish(l_base_conn);
            return -3;
        }
        PQclear(l_res);
        l_query_str = dap_strdup_printf("DROP TABLESPACE IF EXISTS \"%s\"", l_db_name);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Drop tablespace failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            PQfinish(l_base_conn);
            return -4;
        }
        PQclear(l_res);
        // Check paths and create them if nessesary
        if (!dap_dir_test(a_filename_dir)) {
            log_it(L_NOTICE, "No directory %s, trying to create...", a_filename_dir);
            dap_mkdir_with_parents(a_filename_dir);
            if (!dap_dir_test(a_filename_dir)) {
                char l_errbuf[255];
                l_errbuf[0] = '\0';
                strerror_r(errno, l_errbuf, sizeof(l_errbuf));
                log_it(L_ERROR, "Can't create directory, error code %d, error string \"%s\"", errno, l_errbuf);
                return -1;
            }
            log_it(L_NOTICE,"Directory created");
            chown(a_filename_dir, getpwnam("postgres")->pw_uid, -1);
        }
        l_query_str = dap_strdup_printf("CREATE TABLESPACE \"%s\" LOCATION '%s'", l_db_name, a_filename_dir);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Create tablespace failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            PQfinish(l_base_conn);
            return -5;
        }
        chmod(a_filename_dir, S_IRWXU | S_IRWXG | S_IRWXO);
        PQclear(l_res);
        l_query_str = dap_strdup_printf("CREATE DATABASE \"%s\" WITH TABLESPACE \"%s\"", l_db_name, l_db_name);
        l_res = PQexec(l_base_conn, l_query_str);
        DAP_DELETE(l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Create database failed with message: \"%s\"", PQresultErrorMessage(l_res));
            PQclear(l_res);
            PQfinish(l_base_conn);
            return -6;
        }
        PQclear(l_res);
        PQfinish(l_base_conn);
    }
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
    a_drv_callback->read_cond_store_obj = dap_db_driver_pgsql_read_cond_store_obj;
    a_drv_callback->read_last_store_obj = dap_db_driver_pgsql_read_last_store_obj;
    a_drv_callback->get_groups_by_mask  = dap_db_driver_pgsql_get_groups_by_mask;
    a_drv_callback->read_count_store = dap_db_driver_pgsql_read_count_store;
    a_drv_callback->is_obj = dap_db_driver_pgsql_is_obj;
    a_drv_callback->deinit = dap_db_driver_pgsql_deinit;
    a_drv_callback->flush = dap_db_driver_pgsql_flush;
    return 0;
}


int dap_db_driver_pgsql_deinit(void)
{
    pthread_rwlock_wrlock(&s_db_rwlock);
    for (int j = 0; j < DAP_PGSQL_POOL_COUNT; j++)
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
    s_trans_conn = s_pgsql_get_connection();
    if (!s_trans_conn)
        return -1;
    pthread_rwlock_wrlock(&s_db_rwlock);
    PGresult *l_res = PQexec(s_trans_conn, "BEGIN");
    if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
        log_it(L_ERROR, "Begin transaction failed with message: \"%s\"", PQresultErrorMessage(l_res));
        pthread_rwlock_unlock(&s_db_rwlock);
        s_pgsql_free_connection(s_trans_conn);
        s_trans_conn = NULL;
    }
    return 0;
}

/**
 * End of transaction
 */
int dap_db_driver_pgsql_end_transaction(void)
{
    if (s_trans_conn)
        return -1;
    PGresult *l_res = PQexec(s_trans_conn, "COMMIT");
    if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
        log_it(L_ERROR, "End transaction failed with message: \"%s\"", PQresultErrorMessage(l_res));
    }
    pthread_rwlock_unlock(&s_db_rwlock);
    s_pgsql_free_connection(s_trans_conn);
    s_trans_conn = NULL;
    return 0;
}

/**
 * Create table
 *
 * return 0 if Ok, else error code
 */
static int s_pgsql_create_group_table(const char *a_table_name, PGconn *a_conn)
{
    if (!a_table_name)
        return -1;
    int l_ret = 0;
    char *l_query_str = dap_strdup_printf("CREATE TABLE \"%s\""
                                          "(obj_id BIGSERIAL PRIMARY KEY, obj_ts BIGINT, "
                                          "obj_key TEXT UNIQUE, obj_val BYTEA)",
                                          a_table_name);
    PGresult *l_res = PQexec(a_conn, l_query_str);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
        log_it(L_ERROR, "Create table failed with message: \"%s\"", PQresultErrorMessage(l_res));
        l_ret = -3;
    }
    PQclear(l_res);
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
                                        "obj_id = EXCLUDED.obj_id, obj_ts = EXCLUDED.obj_ts, obj_val = EXCLUDED.obj_val;",
                                        a_store_obj->group,  a_store_obj->key);

        // execute add request
        l_res = PQexecParams(l_conn, l_query_str, 2, NULL, l_param_vals, l_param_lens, l_param_formats, 0);
        DAP_DELETE(a_store_obj->value);
        DAP_DELETE(a_store_obj->key);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            if (s_pgsql_create_group_table(a_store_obj->group, l_conn) == 0) {
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
            l_query_str = dap_strdup_printf("DELETE FROM \"%s\" WHERE obj_key = '%s'",
                                            a_store_obj->group, a_store_obj->key);
        // remove all group
        else
            l_query_str = dap_strdup_printf("DROP TABLE \"%s\"", a_store_obj->group);
        DAP_DELETE(a_store_obj->key);
        // execute delete request
        l_res = PQexec(l_conn, l_query_str);
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE)) {
                log_it(L_ERROR, "Delete object failed with message: \"%s\"", PQresultErrorMessage(l_res));
                l_ret = -4;
            }
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
            a_obj->id = be64toh(*(uint64_t *)PQgetvalue(a_res, a_row, i));
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
       l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" WHERE obj_key = '%s'", a_group, a_key);
    } else {
        if (a_count_out && *a_count_out)
            l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" ORDER BY obj_id ASC LIMIT %d", a_group, *a_count_out);
        else
            l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" ORDER BY obj_id ASC", a_group);
    }

    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE))
            log_it(L_ERROR, "Read objects failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return NULL;
    }

    // parse reply
    size_t l_count = PQntuples(l_res);
    dap_store_obj_t *l_obj = l_count ? DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * l_count) : NULL;
    for (int i = 0; i < l_count; i++) {
        // fill currrent item
        dap_store_obj_t *l_obj_cur = l_obj + i;
        s_pgsql_fill_object(a_group, l_obj_cur, l_res, i);
    }
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    if (a_count_out)
        *a_count_out = l_count;
    return l_obj;
}

/**
 * Read last item
 *
 * a_group - group name
 */
dap_store_obj_t *dap_db_driver_pgsql_read_last_store_obj(const char *a_group)
{
    if (!a_group)
        return NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return NULL;
    }
    char *l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" ORDER BY obj_id DESC LIMIT 1", a_group);
    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE))
            log_it(L_ERROR, "Read last object failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return NULL;
    }
    dap_store_obj_t *l_obj = NULL;
    if (PQntuples(l_res)) {
        l_obj = DAP_NEW_Z(dap_store_obj_t);
        s_pgsql_fill_object(a_group, l_obj, l_res, 0);
    }
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
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
dap_store_obj_t *dap_db_driver_pgsql_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out)
{
    if (!a_group)
        return NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return NULL;
    }
    char *l_query_str;
    if (a_count_out && *a_count_out)
        l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" WHERE obj_id >= '%"DAP_UINT64_FORMAT_U"' "
                                        "ORDER BY obj_id ASC LIMIT %d", a_group, a_id, *a_count_out);
    else
        l_query_str = dap_strdup_printf("SELECT * FROM \"%s\" WHERE obj_id >= '%"DAP_UINT64_FORMAT_U"' "
                                        "ORDER BY obj_id ASC", a_group, a_id);
    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE))
            log_it(L_ERROR, "Conditional read objects failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return NULL;
    }

    // parse reply
    size_t l_count = PQntuples(l_res);
    dap_store_obj_t *l_obj = l_count ? DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * l_count) : NULL;
    for (int i = 0; i < l_count; i++) {
        // fill currrent item
        dap_store_obj_t *l_obj_cur = l_obj + i;
        s_pgsql_fill_object(a_group, l_obj_cur, l_res, i);
    }
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    if (a_count_out)
        *a_count_out = l_count;
    return l_obj;
}


dap_list_t *dap_db_driver_pgsql_get_groups_by_mask(const char *a_group_mask)
{
    if (!a_group_mask)
        return NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return NULL;
    }
    const char *l_query_str = "SELECT tablename FROM pg_catalog.pg_tables WHERE "
                              "schemaname != 'information_schema' AND schemaname != 'pg_catalog'";
    PGresult *l_res = PQexec(l_conn, l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        log_it(L_ERROR, "Read tables failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return NULL;
    }

    dap_list_t *l_ret_list = NULL;
    for (int i = 0; i < PQntuples(l_res); i++) {
        char *l_table_name = (char *)PQgetvalue(l_res, i, 0);
        if(!dap_fnmatch(a_group_mask, l_table_name, 0))
            l_ret_list = dap_list_prepend(l_ret_list, dap_strdup(l_table_name));
    }
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    return l_ret_list;
}

size_t dap_db_driver_pgsql_read_count_store(const char *a_group, uint64_t a_id)
{
    if (!a_group)
        return 0;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return 0;
    }
    char *l_query_str = dap_strdup_printf("SELECT count(*) FROM \"%s\" WHERE obj_id >= '%"DAP_UINT64_FORMAT_U"'",
                                          a_group, a_id);
    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE))
            log_it(L_ERROR, "Count objects failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return 0;
    }
    size_t l_ret = be64toh(*(uint64_t *)PQgetvalue(l_res, 0, 0));
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    return l_ret;
}

bool dap_db_driver_pgsql_is_obj(const char *a_group, const char *a_key)
{
    if (!a_group)
        return NULL;
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return NULL;
    }
    char *l_query_str = dap_strdup_printf("SELECT EXISTS(SELECT * FROM \"%s\" WHERE obj_key = '%s')", a_group, a_key);
    PGresult *l_res = PQexecParams(l_conn, l_query_str, 0, NULL, NULL, NULL, NULL, 1);
    DAP_DELETE(l_query_str);
    if (PQresultStatus(l_res) != PGRES_TUPLES_OK) {
        if (strcmp(PQresultErrorField(l_res, PG_DIAG_SQLSTATE), PGSQL_INVALID_TABLE))
            log_it(L_ERROR, "Existance check of object failed with message: \"%s\"", PQresultErrorMessage(l_res));
        PQclear(l_res);
        s_pgsql_free_connection(l_conn);
        return 0;
    }
    int l_ret = *PQgetvalue(l_res, 0, 0);
    PQclear(l_res);
    s_pgsql_free_connection(l_conn);
    return l_ret;
}

int dap_db_driver_pgsql_flush()
{
    PGconn *l_conn = s_pgsql_get_connection();
    if (!l_conn) {
        log_it(L_ERROR, "Can't pick PostgreSQL connection from pool");
        return -4;
    }
    int l_ret = 0;
    PGresult *l_res = PQexec(l_conn, "CHECKPOINT");
    if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
        log_it(L_ERROR, "Flushing database on disk failed with message: \"%s\"", PQresultErrorMessage(l_res));
        l_ret = -5;
    }
    PQclear(l_res);
    if (!l_ret) {
        PGresult *l_res = PQexec(l_conn, "VACUUM");
        if (PQresultStatus(l_res) != PGRES_COMMAND_OK) {
            log_it(L_ERROR, "Vaccuming database failed with message: \"%s\"", PQresultErrorMessage(l_res));
            l_ret = -6;
        }
        PQclear(l_res);
    }
    s_pgsql_free_connection(l_conn);
    return l_ret;
}
#endif
