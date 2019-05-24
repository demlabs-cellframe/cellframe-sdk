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
 */

#include <stddef.h>
#include "dap_common.h"
#include "dap_chain_global_db_driver.h"
#include "dap_chain_global_db_driver_sqlite.h"

#define LOG_TAG "db_sqlite"

static sqlite3 *s_db = NULL;

/**
 * SQLite library initialization, no thread safe
 *
 * return 0 if Ok, else error code >0
 */
int dap_db_driver_sqlite_init(const char *a_filename_db)
{
    int l_ret = -1;
    if(sqlite3_threadsafe() && !sqlite3_config(SQLITE_CONFIG_SERIALIZED))
        l_ret = sqlite3_initialize();
    if(l_ret != SQLITE_OK) {
        log_it(L_ERROR, "Can't init sqlite err=%d", l_ret);
        return l_ret;
    }
    char *l_error_message = NULL;
    s_db = dap_db_driver_sqlite_open(a_filename_db, SQLITE_OPEN_READWRITE, &l_error_message);
    if(!s_db) {
        log_it(L_ERROR, "Can't init sqlite err=%d", l_error_message);
        dap_db_driver_sqlite_free(l_error_message);
    }
    return l_ret;
}

int dap_db_driver_sqlite_deinit(void)
{
    return sqlite3_shutdown();
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

    int l_rc = sqlite3_open_v2(a_filename_utf8, &l_db, a_flags | SQLITE_OPEN_FULLMUTEX, NULL);
    // if unable to open the database file
    if(l_rc == SQLITE_CANTOPEN) {
        // try to create database
        l_rc = sqlite3_open_v2(a_filename_utf8, &l_db, a_flags | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_CREATE, NULL);
    }
    if(l_rc != SQLITE_OK)
    {
        if(a_error_message)
            *a_error_message = sqlite3_mprintf("Can't open database: %s\n", sqlite3_errmsg(l_db));
        sqlite3_close(l_db);
        return NULL;
    }
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
 * Execute SQL query to database that does not return data
 *
 * return 0 if Ok, else error code >0
 */
static int dap_db_driver_sqlite_exec(sqlite3 *l_db, const char *l_query, char **l_error_message)
{
    char *l_zErrMsg = NULL;
    int l_rc = sqlite3_exec(l_db, l_query, NULL, 0, &l_zErrMsg);
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

/*
 * Add multiple entries received from remote node to local database.
 * Since we don't know the size, it must be supplied too
 *
 * dap_store_size the count records
 * return 0 if Ok, else error code >0
 */
int dap_db_add1(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
    int l_ret = 0;
    /*   if(a_store_obj == NULL) {
     log_it(L_ERROR, "Invalid Dap store objects passed");
     return -1;
     }
     if(ldb_connect(s_ldb, dap_db_path, 0, NULL) != LDB_SUCCESS) {
     log_it(L_ERROR, "Couldn't connect to database");
     return -2;
     }
     //log_it(L_INFO, "We're about to put %d records into database", a_store_count);
     struct ldb_message *l_msg;
     if(a_store_count == 0) {
     a_store_count = 1;
     }
     for(size_t q = 0; q < a_store_count; q++) {
     // level 3: leased address, single whitelist entity

     // if it is marked, don't save
     if(a_store_obj[q].timestamp == (time_t) -1)
     continue;

     l_msg = ldb_msg_new(s_ldb);
     char dn[256];
     memset(dn, '\0', 256);
     strcat(dn, "cn=");
     strcat(dn, a_store_obj[q].key);
     //strcat(dn, ",ou=addrs_leased,dc=kelvin_nodes");
     strcat(dn, ",ou=");
     strcat(dn, a_store_obj[q].group);
     strcat(dn, ",dc=kelvin_nodes");
     l_msg->dn = ldb_dn_new(s_mem_ctx, s_ldb, dn);
     int l_res = ldb_msg_add_string(l_msg, "cn", a_store_obj[q].key);
     ldb_msg_add_string(l_msg, "objectClass", a_store_obj[q].group);
     ldb_msg_add_string(l_msg, "section", "kelvin_nodes");
     ldb_msg_add_string(l_msg, "description", "Approved Kelvin node");

     struct ldb_val l_val;
     struct ldb_message_element *return_el;
     l_val.data = (uint8_t*) &a_store_obj[q].timestamp;
     l_val.length = sizeof(time_t);
     l_res = ldb_msg_add_value(l_msg, "time", &l_val, &return_el);

     l_val.data = a_store_obj[q].value;
     l_val.length = a_store_obj[q].value_len;
     l_res = ldb_msg_add_value(l_msg, "val", &l_val, &return_el);

     l_ret += dap_db_add_msg(l_msg); // accumulation error codes
     talloc_free(l_msg->dn);
     talloc_free(l_msg);
     }*/
    return l_ret;
}

