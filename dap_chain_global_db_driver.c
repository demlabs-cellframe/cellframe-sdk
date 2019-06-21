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
#include "dap_chain_global_db_driver_cdb.h"
#include "dap_chain_global_db_driver.h"

#define LOG_TAG "db_driver"

static char *s_used_driver = NULL;

//#define USE_WRITE_BUFFER

#ifdef USE_WRITE_BUFFER
static int save_write_buf(void);

// for write buffer
pthread_mutex_t s_mutex_add_start = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_mutex_add_end = PTHREAD_MUTEX_INITIALIZER;
//pthread_rwlock_rdlock
// new data in buffer to write
pthread_mutex_t s_mutex_cond = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t s_cond_add_end; // = PTHREAD_COND_INITIALIZER;
// writing ended
pthread_mutex_t s_mutex_write_end = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t s_cond_write_end; // = PTHREAD_COND_INITIALIZER;

dap_list_t *s_list_begin = NULL;
dap_list_t *s_list_end = NULL;

pthread_t s_write_buf_thread;
volatile static bool s_write_buf_state = 0;
static void* func_write_buf(void * arg);
#endif //USE_WRITE_BUFFER

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
    if(!dap_strcmp(s_used_driver, "cdb"))
        l_ret = dap_db_driver_cdb_init(a_filename_db, &s_drv_callback);
#ifdef USE_WRITE_BUFFER
    if(!l_ret) {
        pthread_condattr_t l_condattr;
        pthread_condattr_init(&l_condattr);
        pthread_condattr_setclock(&l_condattr, CLOCK_MONOTONIC);
        pthread_cond_init(&s_cond_add_end, &l_condattr);
        pthread_cond_init(&s_cond_write_end, &l_condattr);
        // thread for save buffer to database
        s_write_buf_state = true;
        pthread_create(&s_write_buf_thread, NULL, func_write_buf, NULL);
    }
#endif
    return l_ret;
}

/**
 * Shutting down the db library
 */

void dap_db_driver_deinit(void)
{
#ifdef USE_WRITE_BUFFER
    // wait for close thread
    {
        pthread_mutex_lock(&s_mutex_cond);
        pthread_cond_broadcast(&s_cond_add_end);
        pthread_mutex_unlock(&s_mutex_cond);

        s_write_buf_state = false;
        pthread_join(s_write_buf_thread, NULL);
    }

    //save_write_buf();
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
    pthread_cond_destroy(&s_cond_add_end);
#endif
    // deinit driver
    if(s_drv_callback.deinit)
        s_drv_callback.deinit();
    if(s_used_driver){
        DAP_DELETE(s_used_driver);
        s_used_driver = NULL;
    }
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

static size_t dap_db_get_size_pdap_store_obj_t(pdap_store_obj_t store_obj)
{
    size_t size = sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(size_t) + sizeof(time_t)
            + sizeof(uint64_t) + dap_strlen(store_obj->group) +
            dap_strlen(store_obj->key) + store_obj->value_len;
    return size;
}

/**
 * serialization
 * @param a_store_obj_count count of structures store_obj
 * @param a_timestamp create data time
 * @param a_size_out[out] size of output structure
 * @return NULL in case of an error
 */
dap_store_obj_pkt_t *dap_store_packet_multiple(pdap_store_obj_t a_store_obj, time_t a_timestamp,
        size_t a_store_obj_count)
{
    if(!a_store_obj || a_store_obj_count < 1)
        return NULL;
    size_t l_data_size_out = sizeof(uint32_t); // size of output data
    // calculate output structure size
    for(size_t l_q = 0; l_q < a_store_obj_count; ++l_q)
        l_data_size_out += dap_db_get_size_pdap_store_obj_t(&a_store_obj[l_q]);

    dap_store_obj_pkt_t *l_pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t, sizeof(dap_store_obj_pkt_t) + l_data_size_out);
    l_pkt->data_size = l_data_size_out;
    l_pkt->timestamp = a_timestamp;
    uint64_t l_offset = 0;
    uint32_t l_count = (uint32_t) a_store_obj_count;
    memcpy(l_pkt->data + l_offset, &l_count, sizeof(uint32_t));
    l_offset += sizeof(uint32_t);
    for(size_t l_q = 0; l_q < a_store_obj_count; ++l_q) {
        dap_store_obj_t obj = a_store_obj[l_q];
        //uint16_t section_size = (uint16_t) dap_strlen(obj.section);
        uint16_t group_size = (uint16_t) dap_strlen(obj.group);
        uint16_t key_size = (uint16_t) dap_strlen(obj.key);
        memcpy(l_pkt->data + l_offset, &obj.type, sizeof(int));
        l_offset += sizeof(int);
        //memcpy(l_pkt->data + l_offset, &section_size, sizeof(uint16_t));
        //l_offset += sizeof(uint16_t);
        //memcpy(l_pkt->data + l_offset, obj.section, section_size);
        //l_offset += section_size;
        memcpy(l_pkt->data + l_offset, &group_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.group, group_size);
        l_offset += group_size;
        memcpy(l_pkt->data + l_offset, &obj.id, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);
        memcpy(l_pkt->data + l_offset, &obj.timestamp, sizeof(time_t));
        l_offset += sizeof(time_t);
        memcpy(l_pkt->data + l_offset, &key_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.key, key_size);
        l_offset += key_size;
        memcpy(l_pkt->data + l_offset, &obj.value_len, sizeof(size_t));
        l_offset += sizeof(size_t);
        memcpy(l_pkt->data + l_offset, obj.value, obj.value_len);
        l_offset += obj.value_len;
    }
    assert(l_data_size_out == l_offset);
    return l_pkt;
}
/**
 * deserialization
 * @param store_obj_count[out] count of the output structures store_obj
 * @return NULL in case of an error*
 */

dap_store_obj_t *dap_store_unpacket_multiple(const dap_store_obj_pkt_t *pkt, size_t *store_obj_count)
{
    if(!pkt || pkt->data_size < 1)
        return NULL;
    uint64_t offset = 0;
    uint32_t count;
    memcpy(&count, pkt->data, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    dap_store_obj_t *store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, count * sizeof(struct dap_store_obj));
    for(size_t q = 0; q < count; ++q) {
        dap_store_obj_t *obj = store_obj + q;
        uint16_t str_size;
        memcpy(&obj->type, pkt->data + offset, sizeof(int));
        offset += sizeof(int);

        //memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        //offset += sizeof(uint16_t);
        //obj->section = DAP_NEW_Z_SIZE(char, str_size + 1);
        //memcpy(obj->section, pkt->data + offset, str_size);
        //offset += str_size;

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->group = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->group, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&obj->id, pkt->data + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        memcpy(&obj->timestamp, pkt->data + offset, sizeof(time_t));
        offset += sizeof(time_t);

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->key = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->key, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&obj->value_len, pkt->data + offset, sizeof(size_t));
        offset += sizeof(size_t);

        obj->value = DAP_NEW_Z_SIZE(uint8_t, obj->value_len + 1);
        memcpy(obj->value, pkt->data + offset, obj->value_len);
        offset += obj->value_len;
    }
    assert(pkt->data_size == offset);
    if(store_obj_count)
        *store_obj_count = count;
    return store_obj;
}

/**
 * Calc hash for data
 *
 * return hash or NULL
 */
char* dap_chain_global_db_driver_hash(const uint8_t *data, size_t data_size)
{
    if(!data || data_size <= 0)
        return NULL;
    dap_chain_hash_fast_t l_hash;
    memset(&l_hash, 0, sizeof(dap_chain_hash_fast_t));
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
static int wait_data(pthread_mutex_t *a_mutex, pthread_cond_t *a_cond, int l_timeout_ms)
{
    int l_res = 0;
    pthread_mutex_lock(a_mutex);
    // endless waiting
    if(l_timeout_ms == -1)
        l_res = pthread_cond_wait(a_cond, a_mutex);
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
        l_res = pthread_cond_timedwait(a_cond, a_mutex, &l_to);
    }
    pthread_mutex_unlock(a_mutex);
    if(l_res == ETIMEDOUT)
        return 1;
    return l_res;
}

#ifdef USE_WRITE_BUFFER
// return 0 if buffer empty, 1 data present
static bool check_fill_buf(void)
{
    dap_list_t *l_list_begin;
    dap_list_t *l_list_end;
    pthread_mutex_lock(&s_mutex_add_start);
    pthread_mutex_lock(&s_mutex_add_end);
    l_list_end = s_list_end;
    l_list_begin = s_list_begin;
    pthread_mutex_unlock(&s_mutex_add_end);
    pthread_mutex_unlock(&s_mutex_add_start);

    bool l_ret = (l_list_begin != l_list_end) ? 1 : 0;
//    if(l_ret)
//        printf("** Wait s_beg=0x%x s_end=0x%x \n", l_list_begin, l_list_end);
    return l_ret;
}

// wait apply write buffer
static void wait_write_buf()
{
//    printf("** Start wait data\n");
    // wait data
    while(1) {
        if(!check_fill_buf())
            break;
        if(!wait_data(&s_mutex_write_end, &s_cond_write_end, 50))
            break;
    }
//    printf("** End wait data\n");
}

// save data from buffer to database
static int save_write_buf(void)
{
    dap_list_t *l_list_end;
    // fix end of buffer
    pthread_mutex_lock(&s_mutex_add_end);
    l_list_end = s_list_end;
    pthread_mutex_unlock(&s_mutex_add_end);
    // save data from begin to fixed end
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
                    //log_it(L_INFO, "Write item Ok %s/%s\n", l_obj->group, l_obj->key);
                }
                else {
                    log_it(L_ERROR, "Can't write item %s/%s\n", l_obj->group, l_obj->key);
                }
            }

            s_list_begin = dap_list_next(s_list_begin);
//            printf("** ap2*record *l_beg=0x%x l_nex=0x%x d_beg=0x%x l_end=0x%x d_end=0x%x sl_end=0x%x\n", s_list_begin,
            //                  s_list_begin->next, s_list_begin->data, l_list_end, l_list_end->data, s_list_end);

            //printf("** free data=0x%x list=0x%x\n", s_list_begin->prev->data, s_list_begin->prev);
            // free memory
            dap_store_obj_free((dap_store_obj_t*) s_list_begin->prev->data, 1);
            dap_list_free1(s_list_begin->prev);
            s_list_begin->prev = NULL;
            cnt++;
        }
        if(s_drv_callback.transaction_end)
            s_drv_callback.transaction_end();
        //printf("** writing ended cnt=%d\n", cnt);
        // writing ended
        pthread_mutex_lock(&s_mutex_write_end);
        pthread_cond_broadcast(&s_cond_write_end);
        pthread_mutex_unlock(&s_mutex_write_end);
    }
    pthread_mutex_unlock(&s_mutex_add_start);
    return 0;
}

// thread for save data from buffer to database
static void* func_write_buf(void * arg)
{
    while(1) {
        if(!s_write_buf_state)
            break;
        //save_write_buf
        if(save_write_buf() == 0) {
            if(!s_write_buf_state)
                break;
            // wait data
            wait_data(&s_mutex_cond, &s_cond_add_end, 2000); // 2 sec
        }
    }
    pthread_exit(0);
}
#endif //USE_WRITE_BUFFER

int dap_chain_global_db_driver_appy(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    //dap_store_obj_t *l_store_obj = dap_store_obj_copy(a_store_obj, a_store_count);
    if(!a_store_obj || !a_store_count)
        return -1;
#ifdef USE_WRITE_BUFFER
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
            //log_it(L_DEBUG,"First record in list: *!!add record=0x%x / 0x%x    obj=0x%x / 0x%x\n", s_list_end, s_list_end->data, s_list_end->prev);
        }
        else
            s_list_end->data = l_store_obj_cur;
        dap_list_append(s_list_end, NULL);
        s_list_end = dap_list_last(s_list_end);
        //log_it(L_DEBUG, "**+add record l_cur=0x%x / 0x%x l_new=0x%x / 0x%x\n", s_list_end->prev, s_list_end->prev->data,s_list_end, s_list_end->data);
    }
    // buffer changed
    pthread_mutex_lock(&s_mutex_cond);
    pthread_cond_broadcast(&s_cond_add_end);
    pthread_mutex_unlock(&s_mutex_cond);
    pthread_mutex_unlock(&s_mutex_add_end);
    return 0;
#else
    int l_ret = 0;
    // apply to database
    if(a_store_count > 1 && s_drv_callback.transaction_start)
        s_drv_callback.transaction_start();

    if(s_drv_callback.apply_store_obj)
        for(size_t i = 0; i < a_store_count; i++) {
            dap_store_obj_t *l_store_obj_cur = a_store_obj + i;
            assert(l_store_obj_cur);
            if(!s_drv_callback.apply_store_obj(l_store_obj_cur)) {
                //log_it(L_INFO, "Write item Ok %s/%s\n", l_obj->group, l_obj->key);
            }
            else {
                log_it(L_ERROR, "Can't write item %s/%s\n", l_store_obj_cur->group, l_store_obj_cur->key);
                l_ret -= 1;
            }
        }

    if(a_store_count > 1 && s_drv_callback.transaction_end)
        s_drv_callback.transaction_end();
    return l_ret;
#endif

}

int dap_chain_global_db_driver_add(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    for(size_t i = 0; i < a_store_count; i++)
        a_store_obj[i].type = 'a';
    return dap_chain_global_db_driver_appy(a_store_obj, a_store_count);
}

int dap_chain_global_db_driver_delete(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    for(size_t i = 0; i < a_store_count; i++)
        a_store_obj[i].type = 'd';
    return dap_chain_global_db_driver_appy(a_store_obj, a_store_count);
}

/**
 * Read last items
 *
 * a_group - group name
 */
dap_store_obj_t* dap_chain_global_db_driver_read_last(const char *a_group)
{
    dap_store_obj_t *l_ret = NULL;
#ifdef USE_WRITE_BUFFER
    // wait apply write buffer
    wait_write_buf();
#endif
    // read records using the selected database engine
    if(s_drv_callback.read_last_store_obj)
        l_ret = s_drv_callback.read_last_store_obj(a_group);
    return l_ret;
}

/**
 * Read several items
 *
 * a_group - group name
 * a_key - key name, may by NULL, it means reading the whole group
 * a_id - from this id
 * a_count_out[in], how many items to read, 0 - no limits
 * a_count_out[out], how many items was read
 */
dap_store_obj_t* dap_chain_global_db_driver_cond_read(const char *a_group, uint64_t id, size_t *a_count_out)
{
    dap_store_obj_t *l_ret = NULL;
#ifdef USE_WRITE_BUFFER
    // wait apply write buffer
    wait_write_buf();
#endif
    // read records using the selected database engine
    if(s_drv_callback.read_cond_store_obj)
        l_ret = s_drv_callback.read_cond_store_obj(a_group, id, a_count_out);
    return l_ret;
}

/**
 * Read several items
 *
 * a_group - group name
 * a_key - key name, may by NULL, it means reading the whole group
 * a_count_out[in], how many items to read, 0 - no limits
 * a_count_out[out], how many items was read
 */
dap_store_obj_t* dap_chain_global_db_driver_read(const char *a_group, const char *a_key, size_t *a_count_out)
{
    dap_store_obj_t *l_ret = NULL;
#ifdef USE_WRITE_BUFFER
    // wait apply write buffer
    wait_write_buf();
#endif
    // read records using the selected database engine
    if(s_drv_callback.read_store_obj)
        l_ret = s_drv_callback.read_store_obj(a_group, a_key, a_count_out);
    return l_ret;
}
