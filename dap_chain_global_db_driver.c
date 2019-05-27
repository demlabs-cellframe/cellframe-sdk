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
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_hash.h"

#include "dap_chain_global_db_driver_sqlite.h"
#include "dap_chain_global_db_driver.h"

#define LOG_TAG "db_driver"

static char *s_used_driver = NULL;

static int save_write_buf(void);

// for write buffer
pthread_mutex_t s_mutex_add_start = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_mutex_add_end = PTHREAD_MUTEX_INITIALIZER;
//pthread_rwlock_rdlock
pthread_cond_t s_cond_add_end; // = PTHREAD_COND_INITIALIZER;
dap_list_t *s_list_begin = NULL;
dap_list_t *s_list_end = NULL;

pthread_t s_write_buf_thread;
static void* func_write_buf(void * arg);

static dap_db_driver_callbacks_t s_drv_callback;

/**
 * Select driver
 * driver_name may be "ldb", "sqlite"
 *
 * return 0 OK, <0 Error
 */
int dap_db_driver_init(const char *a_driver_name, const char *a_filename_db)
{
    int l_ret = -1;
    if(s_used_driver)
        dap_db_driver_deinit();
    s_used_driver = dap_strdup(a_driver_name);
    memset(&s_drv_callback, 0, sizeof(dap_db_driver_callbacks_t));
    if(!dap_strcmp(s_used_driver, "ldb"))
        l_ret = -1;
    if(!dap_strcmp(s_used_driver, "sqlite"))
        l_ret = dap_db_driver_sqlite_init(a_filename_db, &s_drv_callback);
    if(!l_ret) {
        pthread_condattr_t l_condattr;
        pthread_condattr_init(&l_condattr);
        pthread_condattr_setclock(&l_condattr, CLOCK_MONOTONIC);
        pthread_cond_init(&s_cond_add_end, &l_condattr);
        // thread for save buffer to database
        pthread_create(&s_write_buf_thread, NULL, func_write_buf, NULL);
    }
    return l_ret;
}

/**
 * Shutting down the db library
 */

void dap_db_driver_deinit(void)
{
    save_write_buf();
    pthread_mutex_lock(&s_mutex_add_end);
    pthread_mutex_lock(&s_mutex_add_start);
    while(s_list_begin != s_list_end) {
        // free memory
        dap_store_obj_free((dap_store_obj_t*) s_list_begin->data, 1);
        dap_list_free1(s_list_begin);
        s_list_begin = dap_list_next(s_list_begin);
    }
    //dap_store_obj_free((dap_store_obj_t*) s_list_begin->data, 1);
    dap_list_free1(s_list_begin);
    s_list_begin = s_list_end = NULL;
    pthread_mutex_unlock(&s_mutex_add_start);
    pthread_mutex_unlock(&s_mutex_add_end);
    if(s_drv_callback.deinit)
        s_drv_callback.deinit();

}

dap_store_obj_t* dap_store_obj_copy(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
    if(!a_store_obj || !a_store_count)
        return NULL;
    dap_store_obj_t *l_store_obj = DAP_NEW_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * a_store_count);
    for(size_t i = 0; i < a_store_count; i++) {
        dap_store_obj_t *l_store_obj_dst = l_store_obj + i;
        dap_store_obj_t *l_store_obj_src = a_store_obj + i;
        memcpy(l_store_obj_dst, l_store_obj_src, sizeof(dap_store_obj_t));
        l_store_obj_dst->group = dap_strdup(l_store_obj_src->group);
        l_store_obj_dst->key = dap_strdup(l_store_obj_src->key);
        l_store_obj_dst->value = DAP_NEW_SIZE(uint8_t, l_store_obj_dst->value_len);
        memcpy(l_store_obj_dst->value, l_store_obj_src->value, l_store_obj_dst->value_len);
    }
    return l_store_obj;
}

void dap_store_obj_free(dap_store_obj_t *a_store_obj, size_t a_store_count)
{
    if(!a_store_obj)
        return;
    for(size_t i = 0; i < a_store_count; i++) {
        dap_store_obj_t *l_store_obj_cur = a_store_obj + i;
        DAP_DELETE(l_store_obj_cur->group);
        DAP_DELETE(l_store_obj_cur->key);
        DAP_DELETE(l_store_obj_cur->value);
    }
    DAP_DELETE(a_store_obj);
}

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_db_driver_db_hash(const uint8_t *data, size_t data_size)
{
    if(!data || data_size <= 0)
        return NULL;
    dap_chain_hash_fast_t l_hash;
    dap_hash_fast(data, data_size, &l_hash);
    size_t a_str_max = (sizeof(l_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_fast_to_str(&l_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL;
    }
    return a_str;
}

/**
 * Wait data to write buffer
 * return 0 - Ok, 1 - timeout
 */
static int wait_data(int l_timeout_ms)
{
    int l_res = 0;
    pthread_mutex_lock(&s_mutex_add_end);
    // endless waiting
    if(l_timeout_ms == -1)
        l_res = pthread_cond_wait(&s_cond_add_end, &s_mutex_add_end);
    // waiting no more than timeout in milliseconds
    else {
        struct timespec l_to;
        clock_gettime(CLOCK_MONOTONIC, &l_to);
        int64_t l_nsec_new = l_to.tv_nsec + l_timeout_ms * 1000000ll;
        // if the new number of nanoseconds is more than a second
        if(l_nsec_new > (long) 1e9) {
            l_to.tv_sec += l_nsec_new / (long) 1e9;
            l_to.tv_nsec = l_nsec_new % (long) 1e9;
        }
        else
            l_to.tv_nsec = (long) l_nsec_new;
        l_res = pthread_cond_timedwait(&s_cond_add_end, &s_mutex_add_end, &l_to);
    }
    pthread_mutex_unlock(&s_mutex_add_end);
    if(l_res == ETIMEDOUT)
        return 1;
    return l_res;
}

static int save_write_buf(void)
{
    dap_list_t *l_list_end;
    pthread_mutex_lock(&s_mutex_add_end);
    l_list_end = s_list_end;
    pthread_mutex_unlock(&s_mutex_add_end);

    pthread_mutex_lock(&s_mutex_add_start);
    if(s_list_begin != l_list_end) {
        if(s_drv_callback.transaction_start)
            s_drv_callback.transaction_start();
        int cnt = 0;
        while(s_list_begin != l_list_end) {
            // apply to database
            dap_store_obj_t *l_obj = s_list_begin->data;
            assert(l_obj);
            if(s_drv_callback.apply_store_obj) {
                if(!s_drv_callback.apply_store_obj(l_obj)) {
                    log_it(L_INFO, "Write item Ok %s/%s\n", l_obj->group, l_obj->key);
                }
                else {
                    log_it(L_ERROR, "Can't write item %s/%s\n", l_obj->group, l_obj->key);
                }
            }

            s_list_begin = dap_list_next(s_list_begin);
            // free memory
            dap_store_obj_free((dap_store_obj_t*) s_list_begin->prev->data, 1);
            dap_list_free1(s_list_begin->prev);
            s_list_begin->prev = NULL;
            cnt++;

        }
        if(s_drv_callback.transaction_end)
            s_drv_callback.transaction_end();
    }
    pthread_mutex_unlock(&s_mutex_add_start);
    // wait data
    //wait_data

}

static void* func_write_buf(void * arg)
{
    while(1) {
        //save_write_buf
        if(save_write_buf() == 0)
            // wait data
            wait_data(2000); // 2 sec
    }
}

int dap_db_add(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    //dap_store_obj_t *l_store_obj = dap_store_obj_copy(a_store_obj, a_store_count);
    if(!a_store_obj || !a_store_count)
        return -1;
    // add all records into write buffer
    pthread_mutex_lock(&s_mutex_add_end);
    for(size_t i = 0; i < a_store_count; i++) {
        dap_store_obj_t *l_store_obj_cur = dap_store_obj_copy(a_store_obj + i, 1);
        // first record in buf
        if(!s_list_end) {
            s_list_end = dap_list_append(s_list_end, l_store_obj_cur);
            pthread_mutex_lock(&s_mutex_add_start);
            s_list_begin = s_list_end;
            pthread_mutex_unlock(&s_mutex_add_start);
        }
        else
            s_list_end->data = l_store_obj_cur;
        s_list_end = dap_list_append(s_list_end, NULL);
        s_list_end = dap_list_last(s_list_end);
    }
    // buffer changed
    pthread_cond_broadcast(&s_cond_add_end);
    pthread_mutex_unlock(&s_mutex_add_end);
}

int dap_db_delete(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    dap_db_add(a_store_obj, a_store_count);
}

dap_store_obj_t* dap_db_read_data(const char *a_group, const char *a_key)
{
    // apply write buffer
    save_write_buf();
    // read record
    if(s_drv_callback.read_store_obj)
        s_drv_callback.read_store_obj(a_group, a_key);
}
