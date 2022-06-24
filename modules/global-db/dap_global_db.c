/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Demlabs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "uthash.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_chain_common.h"
#include "dap_time.h"
#include "dap_context.h"
#include "dap_worker.h"
#include "dap_stream_worker.h"
#include "dap_proc_thread.h"
#define LOG_TAG "dap_global_db"

#include "dap_chain_global_db.h"
#include "dap_global_db_sync.h"
#include "dap_chain_global_db_driver.h"

bool g_dap_global_db_debug_more = false;                                         /* Enable extensible debug output */


// Queue I/O message op code
enum queue_io_msg_opcode{
    MSG_OPCODE_UNDEFINED = 0,
    MSG_OPCODE_GET,
    MSG_OPCODE_GET_RAW,
    MSG_OPCODE_GET_DEL_TS,
    MSG_OPCODE_GET_LAST,
    MSG_OPCODE_GET_LAST_RAW,
    MSG_OPCODE_GET_ALL,
    MSG_OPCODE_GET_ALL_RAW,
    MSG_OPCODE_SET,
    MSG_OPCODE_SET_RAW,
    MSG_OPCODE_SET_MULTIPLE,
    MSG_OPCODE_PIN,
    MSG_OPCODE_UNPIN,
    MSG_OPCODE_DELETE,
    MSG_OPCODE_FLUSH,
    MSG_OPCODE_CONTEXT_EXEC
};


// Queue i/o message
struct queue_io_msg{
    enum queue_io_msg_opcode opcode; // Opcode

    // For each message opcode we have only one callback
    union{
        dap_global_db_callback_t             callback;
        dap_global_db_callback_result_t      callback_result;
        dap_global_db_callback_result_raw_t  callback_result_raw;
        dap_global_db_callback_results_t     callback_results;
        dap_global_db_callback_results_raw_t callback_results_raw;
    };
    // Custom argument passed to the callback
    void *  callback_arg;
    union{
        struct{ // Raw request
            dap_store_obj_t * values_raw;
            size_t values_raw_count;
            size_t values_raw_shift;
        };
        struct{ //deserialized requests
            // Different variant of message params
            union{
                // values for multile set
                struct{
                    dap_global_db_obj_t * values;
                    size_t values_count;
                };

                // Values for get multiple request
                struct{
                    uint64_t values_shift; // For multiple records request here stores next request id
                    uint64_t values_total; // Total values
                    size_t values_page_size; // Maximum size of results page request. 0 means unlimited
                    // TODO implement processing of this value
                };

                // Value for singe request
                struct{
                    void *  value;
                    size_t  value_length;
                    bool    value_is_pinned;
                };

            };
            char * group;  // Group
            char * key; // Key
        };
    };

};

static uint32_t s_global_db_version = 0; // Current GlobalDB version
static pthread_cond_t s_check_db_cond = PTHREAD_COND_INITIALIZER; // Check version condition
static pthread_mutex_t s_check_db_mutex = PTHREAD_MUTEX_INITIALIZER; // Check version condition mutex
static int s_check_db_ret = 0; // Check version return value

static const char * s_storage_path = NULL; // GlobalDB storage path
static const char * s_driver_name = NULL; // GlobalDB driver name

static dap_context_t * s_context = NULL;  // GlobalDB own context
static struct dap_global_db_context * s_context_global_db = NULL; // GlobalDB own context custom extension

// Version check& update functiosn
static int s_check_db_version();
static void s_check_db_version_callback_get (dap_global_db_context_t * a_global_db_context, int a_errno, const char * a_group, const char * a_key,
                                             const void * a_value, const size_t a_value_len,
                                             dap_nanotime_t value_ts,bool a_is_pinned, void * a_arg);
static void s_check_db_version_callback_set (dap_global_db_context_t * a_global_db_context, int a_errno, const char * a_group, const char * a_key,
                                             const void * a_value, const size_t a_value_len,
                                             dap_nanotime_t value_ts,bool a_is_pinned, void * a_arg);

// GlobalDB context start/stop callbacks
static void s_context_callback_started( dap_context_t * a_context, void *a_arg);
static void s_context_callback_stopped( dap_context_t * a_context, void *a_arg);

// Queue i/o processing callback
static void s_queue_io_callback( dap_events_socket_t * a_es, void * a_arg);

// Queue i/o message processing functions
static bool s_msg_opcode_get(struct queue_io_msg * a_msg);
static bool s_msg_opcode_get_raw(struct queue_io_msg * a_msg);
static bool s_msg_opcode_get_del_ts(struct queue_io_msg * a_msg);
static bool s_msg_opcode_get_last(struct queue_io_msg * a_msg);
static bool s_msg_opcode_get_all(struct queue_io_msg * a_msg);
static bool s_msg_opcode_get_all_raw(struct queue_io_msg * a_msg);
static bool s_msg_opcode_set(struct queue_io_msg * a_msg);
static bool s_msg_opcode_set_raw(struct queue_io_msg * a_msg);

static bool s_msg_opcode_set_multiple(struct queue_io_msg * a_msg);
static bool s_msg_opcode_pin(struct queue_io_msg * a_msg);
static bool s_msg_opcode_unpin(struct queue_io_msg * a_msg);
static bool s_msg_opcode_delete(struct queue_io_msg * a_msg);
static bool s_msg_opcode_flush(struct queue_io_msg * a_msg);
static bool s_msg_opcode_context_exec(struct queue_io_msg * a_msg);

// Free memor for queue i/o message
static void s_queue_io_msg_delete( struct queue_io_msg * a_msg);

// Delete history add and del
static int s_record_del_history_add( char *a_key, char *a_group, uint64_t a_timestamp);
static int s_record_del_history_del( char *a_key,  char *a_group);

// Call notificators
static void s_change_notify(dap_store_obj_t * a_store_obj, char a_opcode);





/**
 * @brief dap_global_db_init
 * @param a_path
 * @param a_driver
 * @return
 */
int dap_global_db_init(const char * a_storage_path, const char * a_driver_name)
{
    int l_rc = 0;
    static bool s_is_check_version = false;

    dap_global_db_sync_init();

    if ( a_storage_path == NULL && s_storage_path == NULL ){
        log_it(L_CRITICAL, "Can't initialize GlobalDB without storage path");
    }

    if ( a_driver_name == NULL && a_driver_name == NULL ){
        log_it(L_CRITICAL, "Can't initialize GlobalDB without driver name");
    }

    // For reinitialization it could be NULL but s_storage_path and s_driver_name have to be defined before

    if(a_storage_path)
        s_storage_path = dap_strdup(a_storage_path);

    if(a_driver_name)
        s_driver_name = dap_strdup(a_driver_name);

    // Debug config
    g_dap_global_db_debug_more = dap_config_get_item_bool(g_config, "global_db", "debug_more");


    // Driver initalization
    if( (l_rc = dap_db_driver_init(s_driver_name, s_storage_path, true))  )
        return  log_it(L_CRITICAL, "Hadn't initialized DB driver \"%s\" on path \"%s\", code: %d",
                       s_driver_name, s_storage_path, l_rc), l_rc;

    // Create and run its own context
    if(s_context == NULL){
        s_context = dap_context_new();
        s_context->_inheritor = s_context_global_db = DAP_NEW_Z(struct dap_global_db_context);
        s_context_global_db->context = s_context;
        if (dap_context_run(s_context, -1, DAP_CONTEXT_POLICY_DEFAULT, 0, DAP_CONTEXT_FLAG_WAIT_FOR_STARTED,
                            s_context_callback_started, s_context_callback_stopped, NULL) != 0 ){
            l_rc = -2;
            goto lb_return;
        }
    }

    // Check version and update if need it
    if(!s_is_check_version){

        s_is_check_version = true;

        if ( (l_rc = s_check_db_version()) )
            return  log_it(L_ERROR, "GlobalDB version changed, please export or remove old version!"), l_rc;
    }

lb_return:
    if (l_rc == 0 )
        log_it(L_NOTICE, "GlobalDB initialized");
    else
        log_it(L_CRITICAL, "GlobalDB wasn't initialized, code %d", l_rc);

    return l_rc;
}

/**
 * @brief dap_global_db_deinit
 */
void dap_global_db_deinit()
{
    dap_db_driver_deinit();
    dap_global_db_sync_deinit();
}

/**
 * @brief dap_global_db_get
 * @details Get record value from GlobalDB group by key
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_result = a_callback;
    l_msg->callback_arg = a_arg;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_get
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get(struct queue_io_msg * a_msg)
{
    size_t l_count_records = 0;
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read( a_msg->group,
                                                                     a_msg->key,
                                                                     &l_count_records);
    if(l_store_obj != NULL && l_count_records>=1){
        if(a_msg->callback_result)
        a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_SUCCESS, l_store_obj->group, l_store_obj->key,
                               l_store_obj->value, l_store_obj->value_len, l_store_obj->timestamp,
                               l_store_obj->flags & RECORD_PINNED, a_msg->callback_arg );
        dap_store_obj_free(l_store_obj,l_count_records);
    }else if(a_msg->callback_result)
        a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_NO_RESULTS, a_msg->group, a_msg->key,
                               NULL, 0, 0,0, a_msg->callback_arg );
    return true;
}

/**
 * @brief dap_global_db_get_raw
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get_raw(const char * a_group, const char *a_key,dap_global_db_callback_result_raw_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET_RAW;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_result_raw = a_callback;
    l_msg->callback_arg = a_arg;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_get_raw
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get_raw(struct queue_io_msg * a_msg)
{
    bool l_store_obj_delete = true;
    size_t l_count_records = 0;
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read( a_msg->group,
                                                                     a_msg->key,
                                                                     &l_count_records);


    if(a_msg->callback_result_raw)
        l_store_obj_delete = a_msg->callback_result_raw (s_context_global_db,
                                                         l_store_obj ? DAP_GLOBAL_DB_RC_SUCCESS:
                                                                       DAP_GLOBAL_DB_RC_NO_RESULTS, l_store_obj,
                                                          a_msg->callback_arg );
    if (l_store_obj && l_store_obj_delete)
        dap_store_obj_free(l_store_obj,l_count_records);
    return true;
}

/**
 * @brief dap_global_db_get_del_ts
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get_del_ts(const char * a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET_DEL_TS;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_result = a_callback;
    l_msg->callback_arg = a_arg;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get_del_ts request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_get_del_ts
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get_del_ts(struct queue_io_msg * a_msg)
{
    uint64_t l_timestamp = 0;
    dap_store_obj_t l_store_obj_del = { 0 };
    char l_group[DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX];
    size_t l_count_out = 0;
    dap_store_obj_t *l_obj;

    if(a_msg->key && a_msg->group){
        l_store_obj_del.key = a_msg->key;
        dap_snprintf(l_group, sizeof(l_group) - 1,  "%s.del", a_msg->group);
        l_store_obj_del.group = l_group;

        if (dap_chain_global_db_driver_is(l_store_obj_del.group, l_store_obj_del.key))
        {
            if ( (l_obj = dap_chain_global_db_driver_read(l_store_obj_del.group, l_store_obj_del.key, &l_count_out)) )
            {
                if ( (l_count_out > 1) )
                    log_it(L_WARNING, "Got more then 1 records (%zu) for group '%s'", l_count_out, l_group);

                l_timestamp = l_obj->timestamp;
                dap_store_obj_free(l_obj, l_count_out);
            }
        }
    }

    if(l_timestamp){
        if(a_msg->callback_result)
            a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_SUCCESS, a_msg->group, a_msg->key,
                               NULL, 0, l_timestamp,
                               false, a_msg->callback_arg );
    }else if(a_msg->callback_result)
        a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_NO_RESULTS, a_msg->group, a_msg->key,
                               NULL, 0, 0,0, a_msg->callback_arg );
    return true;
}

/**
 * @brief dap_global_db_get_last
 * @details Get the last value in GlobalDB group
 * @param a_group
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get_last(const char * a_group, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get_last");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET_LAST;
    l_msg->group = dap_strdup(a_group);
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get_last request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_get_last
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get_last(struct queue_io_msg * a_msg)
{
    dap_store_obj_t *l_store_obj = dap_chain_global_db_driver_read_last(a_msg->group);
    if(l_store_obj){
        if(a_msg->callback_result)
            a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_SUCCESS, l_store_obj->group, l_store_obj->key,
                               l_store_obj->value, l_store_obj->value_len, l_store_obj->timestamp,
                               l_store_obj->flags & RECORD_PINNED, a_msg->callback_arg );
        dap_store_obj_free(l_store_obj,1);
    }else if(a_msg->callback_result)
        a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_NO_RESULTS, a_msg->group, a_msg->key,
                               NULL, 0, 0,0, a_msg->callback_arg );
    return true;
}


/**
 * @brief dap_global_db_get_all Get all records from the group
 * @param a_group
 * @param a_results_page_size
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get_all(const char * a_group,size_t a_results_page_size, dap_global_db_callback_results_t a_callback, void * a_arg )
{
    // TODO make usable a_results_page_size
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get_all");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET_ALL;
    l_msg->group = dap_strdup(a_group);
    l_msg->callback_arg = a_arg;
    l_msg->callback_results = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get_all request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_get_all
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get_all(struct queue_io_msg * a_msg)
{
    size_t l_values_count = 0;
    if(! a_msg->values_total){ // First msg process
        a_msg->values_total = dap_chain_global_db_driver_count(a_msg->group,0);
    }
    dap_store_obj_t *l_store_objs = dap_chain_global_db_driver_cond_read(a_msg->group, a_msg->values_shift , &l_values_count);
    dap_global_db_obj_t *l_objs = NULL;

    // Form objs from store_objs
    if(l_store_objs){
        l_objs = DAP_NEW_Z_SIZE(dap_global_db_obj_t,sizeof(dap_global_db_obj_t)*l_values_count);
        for(int i = 0; i < l_values_count; i++){
            l_objs[i].id = l_store_objs[i].id;
            l_objs[i].is_pinned = l_store_objs[i].flags & RECORD_PINNED;
            l_objs[i].key = l_store_objs[i].key;
            l_objs[i].value = l_store_objs[i].value;
            l_objs[i].timestamp = l_store_objs[i].timestamp;
        }
    }

    bool l_delete_objs = true;
    // Call callback if present
    if(a_msg->callback_results)
        l_delete_objs = a_msg->callback_results(s_context_global_db,  l_objs? DAP_GLOBAL_DB_RC_SUCCESS:DAP_GLOBAL_DB_RC_NO_RESULTS
                                , a_msg->group, a_msg->key, a_msg->values_total, l_values_count,
                                 a_msg->values_shift,
                                 l_objs, a_msg->callback_arg );
    // Clean memory
    if(l_store_objs)
        dap_store_obj_free(l_store_objs,l_values_count);
    if(l_objs && l_delete_objs)
        DAP_DELETE(l_objs);

    // Check for values_shift overflow and update it
    if(l_values_count && a_msg->values_shift< UINT64_MAX - l_values_count &&
            l_values_count + a_msg->values_shift < a_msg->values_total ){
        a_msg->values_shift += l_values_count;

    }

    if( a_msg->values_shift < a_msg->values_total){ // Have to process callback again
        int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,a_msg);
        if ( l_ret ){
            log_it(L_ERROR,"Can't resend i/o message for opcode GET_ALL after value shift %"
                   DAP_UINT64_FORMAT_U" error code %d", a_msg->values_shift,l_ret);
            return true;
        }else
            return false; // Don't delete it because it just sent again to the queue
    }else // All values are sent
        return true;
}

/**
 * @brief dap_global_db_get_all_raw
 * @param a_group
 * @param a_first_id
 * @param a_results_page_size
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_get_all_raw(const char * a_group, uint64_t a_first_id,size_t a_results_page_size, dap_global_db_callback_results_raw_t a_callback, void * a_arg )
{
    // TODO make usable a_results_page_size

    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_get_all");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_GET_ALL;
    l_msg->group = dap_strdup(a_group);
    l_msg->values_raw_shift = a_first_id;
    l_msg->callback_arg = a_arg;
    l_msg->callback_results_raw = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec get_all_raw request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief Get all records in raw format inside GlobalDB context
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_get_all_raw(struct queue_io_msg * a_msg)
{
    size_t l_values_count = 0;
    if(! a_msg->values_total){ // First msg process
        a_msg->values_raw_count = dap_chain_global_db_driver_count(a_msg->group,0);
    }
    dap_store_obj_t *l_store_objs = dap_chain_global_db_driver_cond_read(a_msg->group, a_msg->values_raw_shift , &l_values_count);


    // Call callback if present
    if(a_msg->callback_results_raw)
        a_msg->callback_results_raw(s_context_global_db,  l_store_objs? DAP_GLOBAL_DB_RC_SUCCESS:DAP_GLOBAL_DB_RC_NO_RESULTS
                                , a_msg->group, a_msg->key, a_msg->values_raw_count, l_values_count,
                                 a_msg->values_raw_count,
                                 l_store_objs, a_msg->callback_arg );
    // Clean memory
    if(l_store_objs)
        dap_store_obj_free(l_store_objs,l_values_count);

    // Check for values_shift overflow and update it
    if(l_values_count && a_msg->values_raw_count< UINT64_MAX - l_values_count &&
            l_values_count + a_msg->values_raw_count < a_msg->values_raw_count ){
        a_msg->values_raw_count += l_values_count;

    }

    if( a_msg->values_shift < a_msg->values_raw_count){ // Have to process callback again
        int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,a_msg);
        if ( l_ret ){
            log_it(L_ERROR,"Can't resend i/o message for opcode GET_ALL_RAW after value shift %"
                   DAP_UINT64_FORMAT_U" error code %d", a_msg->values_shift,l_ret);
            return true;
        }else
            return false; // Don't delete it because it just sent again to the queue
    }else // All values are sent
        return true;

}


/**
 * @brief Set GlobalDB record, identified with group and key
 * @param a_group Group name
 * @param a_key Key string
 * @param a_value Value data's pointer
 * @param a_value_length Value data's length
 * @param a_pin_value Pin value or not
 * @param a_callback  Callback executed after request processing
 * @param a_arg Argument passed to the callback
 * @return 0 if success, error code if not
 */
int dap_global_db_set(const char * a_group, const char *a_key, const void * a_value, const size_t a_value_length, bool a_pin_value, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_set");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_SET;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec set request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_set
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_set(struct queue_io_msg * a_msg)
{
    dap_store_obj_t l_store_data = { 0 };
    dap_nanotime_t l_ts_now = dap_nanotime_now();
    l_store_data.key = a_msg->key ;
    l_store_data.flags = a_msg->value_is_pinned ? RECORD_PINNED : 0 ;
    l_store_data.value_len = ( a_msg->value_length == (size_t) -1) ?
                dap_strlen( a_msg->value) : a_msg->value_length;
    l_store_data.value = a_msg->value ? a_msg->value : NULL;
    l_store_data.group = a_msg->group ;
    l_store_data.timestamp = l_ts_now;

    int l_res = dap_chain_global_db_driver_add(&l_store_data, 1);
    if (l_res){
        s_record_del_history_del( a_msg->group, a_msg->key);
        if(a_msg->callback_result){
            a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_SUCCESS, a_msg->group, a_msg->key,
                                   a_msg->value, a_msg->value_length, l_ts_now,
                                   a_msg->value_is_pinned , a_msg->callback_arg );
        }
        s_change_notify(&l_store_data, DAP_DB$K_OPTYPE_ADD);
    }else{
        log_it(L_ERROR, "Save error for %s:%s code %d", a_msg->group,a_msg->key, l_res);
        if(a_msg->callback_result)
            a_msg->callback_result(s_context_global_db, DAP_GLOBAL_DB_RC_ERROR , a_msg->group, a_msg->key,
                                   a_msg->value, a_msg->value_length, l_ts_now,
                                   a_msg->value_is_pinned , a_msg->callback_arg );
    }
    return true;
}

/**
 * @brief dap_global_db_set_raw
 * @param a_store_objs
 * @param a_store_objs_count
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_set_raw(dap_store_obj_t * a_store_objs, size_t a_store_objs_count, dap_global_db_callback_results_raw_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_set");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_SET_RAW;
    l_msg->callback_arg = a_arg;
    l_msg->callback_results_raw = a_callback;

    l_msg->values_raw = a_store_objs;
    l_msg->values_raw_count = a_store_objs_count;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec set_raw request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;

}

/**
 * @brief s_msg_opcode_set_raw
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_set_raw(struct queue_io_msg * a_msg)
{
    int l_ret = -1;
    size_t i=0;
    if(a_msg->values_raw_count>0){
        l_ret = dap_chain_global_db_driver_add(a_msg->values_raw,a_msg->values_raw_count);
        if(l_ret == 0){
            for(;  i < a_msg->values_raw_count ; i++ ) {
                s_record_del_history_del(a_msg->values_raw[i].key , a_msg->values_raw[i].group);
                s_change_notify(&a_msg->values_raw[i] , a_msg->values_raw[i].type );
            }
        }else
            log_it(L_ERROR,"Can't save raw gdb data, code %d ", l_ret);
    }
    if(a_msg->callback_results_raw){
        a_msg->callback_results_raw (s_context_global_db,  l_ret==0 ? DAP_GLOBAL_DB_RC_SUCCESS:
                                        DAP_GLOBAL_DB_RC_ERROR, a_msg->group, a_msg->key,
                               a_msg->values_raw_count, 0, a_msg->values_raw_count, a_msg->values_raw ,
                                a_msg->callback_arg );
    }

    return true;
}

/**
 * @brief dap_global_db_set_multiple
 * @param a_group
 * @param a_values
 * @param a_values_count
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_set_multiple(const char * a_group, dap_global_db_obj_t * a_values, size_t a_values_count, dap_global_db_callback_results_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_set");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_SET_MULTIPLE;
    l_msg->group = dap_strdup(a_group);
    l_msg->values = a_values;
    l_msg->values_count = a_values_count;
    l_msg->callback_arg = a_arg;
    l_msg->callback_results = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec set_multiple request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_set_multiple
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_set_multiple(struct queue_io_msg * a_msg)
{
    int l_ret = -1;
    size_t i=0;
    if(a_msg->values_count>0){
        dap_store_obj_t l_store_obj;
        l_ret = 0;
        for(;  i < a_msg->values_count && l_ret == 0  ; i++ ) {
            memset(&l_store_obj,0,sizeof(l_store_obj));
            l_store_obj.type = DAP_DB$K_OPTYPE_ADD;
            l_store_obj.flags = a_msg->values[i].is_pinned;
            l_store_obj.key =  a_msg->values[i].key;
            l_store_obj.group = a_msg->group;
            l_store_obj.value = a_msg->values[i].value;
            l_store_obj.value_len = a_msg->values[i].value_len;
            l_store_obj.timestamp = a_msg->values[i].timestamp;
            s_record_del_history_del(a_msg->values[i].key, a_msg->group);
            l_ret = dap_chain_global_db_driver_add(&l_store_obj,1);
            s_change_notify(&l_store_obj , DAP_DB$K_OPTYPE_ADD);

        }
    }
    if(a_msg->callback_results){
        a_msg->callback_results(s_context_global_db,  l_ret==0 ? DAP_GLOBAL_DB_RC_SUCCESS:
                                        DAP_GLOBAL_DB_RC_ERROR, a_msg->group, a_msg->key,
                               i, 0, a_msg->values_count, a_msg->values ,
                                a_msg->callback_arg );
    }

    return true;
}

/**
 * @brief dap_global_db_pin
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_pin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_pin");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_PIN;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec pin request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_pin
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_pin(struct queue_io_msg * a_msg)
{
    return true;
}

/**
 * @brief dap_global_db_unpin
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_unpin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_unpin");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_UNPIN;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec unpin request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_unpin
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_unpin(struct queue_io_msg * a_msg)
{
    return true;
}

/**
 * @brief dap_global_db_delete
 * @param a_group
 * @param a_key
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_del(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_delete");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_DELETE;
    l_msg->group = dap_strdup(a_group);
    l_msg->key = dap_strdup(a_key);
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec del request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_delete
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_delete(struct queue_io_msg * a_msg)
{

    int l_res = dap_global_db_del_unsafe(s_context_global_db, a_msg->group, a_msg->key);

    if(a_msg->callback_result){
        a_msg->callback_result(s_context_global_db,  l_res==0 ? DAP_GLOBAL_DB_RC_SUCCESS:
                                        DAP_GLOBAL_DB_RC_ERROR,
                                a_msg->group, a_msg->key,
                               NULL, 0, 0 , false, a_msg->callback_arg );
    }

    return true;
}

/**
 * @brief Deallocates memory of an objs array.
 * @param objs a pointer to the first object of the array
 * @param a_count a number of objects in the array
 * @return (none)
 */
void dap_global_db_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count)
{
dap_global_db_obj_t *l_obj;

    if ( !a_objs || !a_count )                                              /* Sanity checks */
        return;

    for(l_obj = a_objs; a_count--; l_obj++)                                 /* Run over array's elements */
    {
        DAP_DELETE(l_obj->key);
        DAP_DELETE(l_obj->value);
    }

    DAP_DELETE(a_objs);                                                     /* Finaly kill the the array */
}

/**
 * @brief The objs_get struct
 */
struct objs_get{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    dap_global_db_obj_t * objs;
    size_t objs_count;
};

/**
 * @brief s_objs_get_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_objs_get_callback (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key, const size_t a_values_total,  const size_t a_values_shift,
                                                  const size_t a_values_count, dap_global_db_obj_t * a_values, void * a_arg)
{
    struct objs_get * l_args = (struct objs_get *) a_arg;
    l_args->objs = a_values;
    l_args->objs_count = a_values_count;
    pthread_mutex_lock(&l_args->mutex);
    pthread_cond_broadcast(&l_args->cond);
    pthread_mutex_unlock(&l_args->mutex);
    return false;
}

/**
 * @brief Sync (blocking) function for retrieving of list of GDB content
 * @param a_group
 * @param a_objs_count
 * @return Group's objects
 */
dap_global_db_obj_t* dap_global_db_objs_get(const char *a_group, size_t *a_objs_count)
{
    struct objs_get * l_args = DAP_NEW_Z(struct objs_get);
    pthread_mutex_init(&l_args->mutex,NULL);
    pthread_cond_init(&l_args->cond,NULL);
    pthread_mutex_lock(&l_args->mutex);
    dap_global_db_get_all(a_group,0,s_objs_get_callback, l_args);
    pthread_cond_wait(&l_args->cond, &l_args->mutex);
    pthread_mutex_unlock(&l_args->mutex);
    pthread_mutex_destroy(&l_args->mutex);
    pthread_cond_destroy(&l_args->cond);

    dap_global_db_obj_t * l_ret = l_args->objs;
    if(l_args->objs_count)
        *a_objs_count = l_args->objs_count;
    DAP_DELETE(l_args);
    return l_ret;
}


/**
 * @brief The objs_set struct
 */
struct sync_op_result{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int result;
};

/**
 * @brief s_objs_set_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_value_ts
 * @param a_is_pinned
 * @param a_arg
 */
static void s_sync_op_result_callback (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, dap_nanotime_t a_value_ts, bool a_is_pinned, void * a_arg)
{
    struct sync_op_result * l_args = (struct sync_op_result *) a_arg;
    l_args->result = a_rc;
    pthread_mutex_lock(&l_args->mutex);
    pthread_cond_broadcast(&l_args->cond);
    pthread_mutex_unlock(&l_args->mutex);
}

/**
 * @brief Put value into the GlobalDB and waits for result
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_length
 * @param a_pin_value
 * @return 0 if success others if not
 */
int dap_global_db_set_sync(const char * a_group, const char *a_key, const void * a_value, const size_t a_value_length, bool a_pin_value )
{
    struct sync_op_result * l_args = DAP_NEW_Z(struct sync_op_result);
    pthread_mutex_init(&l_args->mutex,NULL);
    pthread_cond_init(&l_args->cond,NULL);
    pthread_mutex_lock(&l_args->mutex);
    dap_global_db_set(a_group, a_key,a_value,a_value_length, a_pin_value, s_sync_op_result_callback, l_args);
    pthread_cond_wait(&l_args->cond, &l_args->mutex);
    pthread_mutex_unlock(&l_args->mutex);
    pthread_mutex_destroy(&l_args->mutex);
    pthread_cond_destroy(&l_args->cond);

    int l_ret = l_args->result ;
    DAP_DELETE(l_args);
    return l_ret;
}

/**
 * @brief dap_global_db_del_sync
 * @param a_group
 * @param a_key
 * @return
 */
int dap_global_db_del_sync(const char * a_group, const char *a_key )
{
    struct sync_op_result * l_args = DAP_NEW_Z(struct sync_op_result);
    pthread_mutex_init(&l_args->mutex,NULL);
    pthread_cond_init(&l_args->cond,NULL);
    pthread_mutex_lock(&l_args->mutex);
    dap_global_db_del(a_group, a_key, s_sync_op_result_callback, l_args);
    pthread_cond_wait(&l_args->cond, &l_args->mutex);
    pthread_mutex_unlock(&l_args->mutex);
    pthread_mutex_destroy(&l_args->mutex);
    pthread_cond_destroy(&l_args->cond);

    int l_ret = l_args->result ;
    DAP_DELETE(l_args);
    return l_ret;
}

/**
 * @brief The store_obj_get struct
 */
struct store_obj_get{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    byte_t * data;
    size_t data_size;
    dap_nanotime_t ts;
    bool is_pinned;
};

/**
 * @brief s_store_obj_get_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_size
 * @param a_value_ts
 * @param a_is_pinned
 * @param a_arg
 */
static void s_store_obj_get_callback (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key,
                                 const void * a_value, const size_t a_value_size, dap_nanotime_t a_value_ts,
                                 bool a_is_pinned, void * a_arg)
{
    struct store_obj_get * l_args = (struct store_obj_get *) a_arg;
    assert(l_args);

    if( a_value && a_value_size){
        l_args->data = DAP_DUP_SIZE(a_value, a_value_size);
        l_args->data_size = a_value_size;
        l_args->ts = a_value_ts;
    }

    pthread_mutex_lock(&l_args->mutex);
    pthread_cond_broadcast(&l_args->cond);
    pthread_mutex_unlock(&l_args->mutex);
}

/**
 * @brief dap_global_db_gr_get_sync
 * @param a_group
 * @param a_key
 * @param a_data_size
 * @param a_is_pinned
 * @param a_ts
 * @return
 */
byte_t* dap_global_db_get_sync(const char * a_group,const char *a_key, size_t *a_data_size, bool *a_is_pinned, dap_nanotime_t * a_ts)
{
    struct store_obj_get * l_args = DAP_NEW_Z(struct store_obj_get);
    pthread_mutex_init(&l_args->mutex,NULL);
    pthread_cond_init(&l_args->cond,NULL);
    pthread_mutex_lock(&l_args->mutex);



    dap_global_db_get(a_group,a_key, s_store_obj_get_callback, l_args);
    pthread_cond_wait(&l_args->cond, &l_args->mutex);
    pthread_mutex_unlock(&l_args->mutex);
    pthread_mutex_destroy(&l_args->mutex);
    pthread_cond_destroy(&l_args->cond);

    byte_t * l_ret = l_args->data;
    if( l_ret ){
        if( a_data_size)
            *a_data_size = l_args->data_size;
        if( a_is_pinned)
            *a_is_pinned = l_args->is_pinned;
        if( a_ts)
            *a_ts = l_args->ts;
    }
    DAP_DELETE(l_args);
    return l_ret;
}


/**
 * @brief The store_objs_get struct
 */
struct store_objs_get{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    dap_store_obj_t * objs;
    size_t objs_count;
};

static bool s_store_objs_get_callback (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key, const size_t a_values_total,  const size_t a_values_shift,
                                                  const size_t a_values_count, dap_store_obj_t * a_values, void * a_arg)
{
    struct store_objs_get * l_args = (struct store_objs_get *) a_arg;
    l_args->objs = a_values;
    l_args->objs_count = a_values_count;
    pthread_mutex_lock(&l_args->mutex);
    pthread_cond_broadcast(&l_args->cond);
    pthread_mutex_unlock(&l_args->mutex);
    return false;
}

dap_store_obj_t* dap_global_db_store_objs_get_sync(const char *a_group, uint64_t a_first_id, size_t *a_objs_count)
{
    struct store_objs_get * l_args = DAP_NEW_Z(struct store_objs_get);
    pthread_mutex_init(&l_args->mutex,NULL);
    pthread_cond_init(&l_args->cond,NULL);
    pthread_mutex_lock(&l_args->mutex);
    dap_global_db_get_all_raw(a_group,a_first_id, 0,s_store_objs_get_callback, l_args);
    pthread_cond_wait(&l_args->cond, &l_args->mutex);
    pthread_mutex_unlock(&l_args->mutex);
    pthread_mutex_destroy(&l_args->mutex);
    pthread_cond_destroy(&l_args->cond);

    dap_store_obj_t * l_ret = l_args->objs;
    if(l_args->objs_count)
        *a_objs_count = l_args->objs_count;
    DAP_DELETE(l_args);
    return l_ret;

}

/**
 * @brief dap_global_db_del_unsafe
 * @param a_group
 * @param a_key
 * @return
 */
int dap_global_db_del_unsafe(dap_global_db_context_t * a_global_db_context, const char * a_group, const char *a_key)
{
    dap_store_obj_t l_store_obj = {0};

    l_store_obj.key = dap_strdup(a_key);
    l_store_obj.group = dap_strdup(a_group);

    int l_res = dap_chain_global_db_driver_delete(&l_store_obj, 1);

    if (a_key) {
        if (l_res >= 0) {
            // add to Del group
            l_res = s_record_del_history_add(l_store_obj.group, l_store_obj.key, dap_nanotime_now() );
        }
        // do not add to history if l_res=1 (already deleted)
        if (!l_res) {
            l_store_obj.key = l_store_obj.key;
            s_change_notify(&l_store_obj, DAP_DB$K_OPTYPE_DEL);
        }
    }
    DAP_DELETE(l_store_obj.key);
    DAP_DELETE(l_store_obj.group);
    return l_res;
}

/**
 * @brief dap_global_db_flush_sync
 * @return
 */
int dap_global_db_flush_sync()
{
    return dap_db_driver_flush();
}

/**
 * @brief dap_global_db_flush
 * @param a_callback
 * @param a_arg
 * @return
 */
int dap_global_db_flush( dap_global_db_callback_result_t a_callback, void * a_arg )
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_delete");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_FLUSH;
    l_msg->callback_arg = a_arg;
    l_msg->callback_result = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec flush request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;
}

/**
 * @brief s_msg_opcode_flush
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_flush(struct queue_io_msg * a_msg)
{
    int l_res = dap_db_driver_flush();
    if(a_msg->callback_result){
        a_msg->callback_result(s_context_global_db,  l_res==0 ? DAP_GLOBAL_DB_RC_SUCCESS:
                                        DAP_GLOBAL_DB_RC_ERROR,
                                NULL,NULL,NULL, 0, 0 , false, a_msg->callback_arg );
    }
    return true;
}

/**
 * @brief Execute callback in GlobalDB context
 * @param a_callback  Callback function
 * @param arg Custom argument
 * @return 0 if success, others if not
 */
int dap_global_db_context_exec (dap_global_db_callback_t a_callback, void * a_arg)
{
    if(s_context_global_db == NULL){
        log_it(L_ERROR, "GlobalDB context is not initialized, can't call dap_global_db_context_exec");
        return -666;
    }
    struct queue_io_msg * l_msg = DAP_NEW_Z(struct queue_io_msg);
    l_msg->opcode = MSG_OPCODE_CONTEXT_EXEC;
    l_msg->callback_arg = a_arg;
    l_msg->callback = a_callback;

    int l_ret = dap_events_socket_queue_ptr_send(s_context_global_db->queue_io,l_msg);
    if (l_ret != 0){
        log_it(L_ERROR, "Can't exec context_exec request, code %d", l_ret);
        s_queue_io_msg_delete(l_msg);
    }
    return l_ret;

}

/**
 * @brief Execute callback in GlobalDB context
 * @param a_msg
 * @return
 */
static bool s_msg_opcode_context_exec(struct queue_io_msg * a_msg)
{
    if(a_msg->callback)
        a_msg->callback(s_context_global_db, a_msg->callback_arg );
    return true;
}



/**
 * @brief s_queue_io_callback
 * @details Queue I/O process callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_io_callback( dap_events_socket_t * a_es, void * a_arg)
{
    (void) a_es;
    struct queue_io_msg * l_msg = (struct queue_io_msg *) a_arg;
    bool l_msg_delete = false; // if msg resent again it shouldn't be deleted in the end of callback
    assert(l_msg);

    switch(l_msg->opcode){
        case MSG_OPCODE_GET:          l_msg_delete = s_msg_opcode_get(l_msg); break;
        case MSG_OPCODE_GET_RAW:      l_msg_delete = s_msg_opcode_get_raw(l_msg); break;
        case MSG_OPCODE_GET_LAST:     l_msg_delete = s_msg_opcode_get_last(l_msg); break;
        case MSG_OPCODE_GET_ALL:      l_msg_delete = s_msg_opcode_get_all(l_msg); break;
        case MSG_OPCODE_GET_ALL_RAW:  l_msg_delete = s_msg_opcode_get_all_raw(l_msg); break;
        case MSG_OPCODE_SET:          l_msg_delete = s_msg_opcode_set(l_msg); break;
        case MSG_OPCODE_SET_MULTIPLE: l_msg_delete = s_msg_opcode_set_multiple(l_msg); break;
        case MSG_OPCODE_SET_RAW:      l_msg_delete = s_msg_opcode_set_raw(l_msg); break;
        case MSG_OPCODE_PIN:          l_msg_delete = s_msg_opcode_pin(l_msg); break;
        case MSG_OPCODE_UNPIN:        l_msg_delete = s_msg_opcode_unpin(l_msg); break;
        case MSG_OPCODE_DELETE:       l_msg_delete = s_msg_opcode_delete(l_msg); break;
        case MSG_OPCODE_FLUSH:        l_msg_delete = s_msg_opcode_flush(l_msg); break;
        case MSG_OPCODE_CONTEXT_EXEC: l_msg_delete = s_msg_opcode_context_exec(l_msg); break;
        default:{
            log_it(L_WARNING, "Message with undefined opcode %d received in queue_io",
                   l_msg->opcode);
        }
    }
    if( l_msg_delete )
        s_queue_io_msg_delete(l_msg);
}


/**
 * @brief Adds data to the history log
 *
 * @param a_store_data a pointer to an object
 * @return (none)
 */
static void s_change_notify(dap_store_obj_t * a_store_obj, char a_opcode)
{
dap_list_t *l_items_list = dap_global_db_get_sync_groups_all();
    while (l_items_list) {
        for (dap_list_t *it = dap_global_db_get_sync_groups_all(); it; it = it->next) {
            dap_sync_group_item_t *l_sync_group_item = (dap_sync_group_item_t *)it->data;
            if (dap_fnmatch(l_sync_group_item->group_mask, a_store_obj->group, 0))
                continue;
            if(l_sync_group_item->callback_notify) {
                 l_sync_group_item->callback_notify(l_sync_group_item->callback_arg,
                            a_opcode,
                            a_store_obj->group, a_store_obj->key,
                            a_store_obj->value, a_store_obj->value_len);
            }
            return;
        }
        l_items_list = (l_items_list ==  dap_global_db_get_sync_groups_all()) ?
                    dap_global_db_get_sync_groups_extra_all() : NULL;
    }
}


/*
* @brief s_record_del_history_del Deletes info about the deleted object from the database
* @param a_key an object key string, looked like "0x8FAFBD00B..."
* @param a_group a group name string, for example "kelvin-testnet.nodes"
* @return If successful, returns true; otherwise, false.
*/
static int s_record_del_history_del( char *a_group, char *a_key)
{
dap_store_obj_t store_data = {0};
char	l_group[DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX];
int	l_res = 0;

   if(!a_key)
       return false;

   store_data.key = a_key;
   dap_snprintf(l_group, sizeof(l_group) - 1, "%s.del", a_group);
   store_data.group = l_group;

   if ( dap_chain_global_db_driver_is(store_data.group, store_data.key) )
       l_res = dap_chain_global_db_driver_delete(&store_data, 1);

   return  (l_res >= 0);    /*  ? true : false; */
}

/**
 * @brief s_record_del_history_add Adds info about the deleted entry to the database.
 * @param a_key an object key string
 * @param a_group a group name string
 * @param a_timestamp an object time stamp
 * @return True if successful, false otherwise.
 */
static int s_record_del_history_add( char *a_key, char *a_group, uint64_t a_timestamp)
{
dap_store_obj_t store_data = {0};
char	l_group[DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX];
int l_res = -1;

    store_data.key = a_key;
    // group = parent group + '.del'
    dap_snprintf(l_group, sizeof(l_group) - 1, "%s.del", a_group);
    store_data.group = l_group;
    store_data.timestamp = a_timestamp;

    if (!dap_chain_global_db_driver_is(store_data.group, store_data.key))
        l_res = dap_chain_global_db_driver_add(&store_data, 1);

    return  l_res;
}

/**
 * @brief s_queue_io_msg_delete
 * @param a_msg
 */
static void s_queue_io_msg_delete( struct queue_io_msg * a_msg)
{
   if (a_msg->group)
       DAP_DELETE(a_msg->group);
   if (a_msg->key)
       DAP_DELETE(a_msg->key);
   DAP_DELETE(a_msg);
}


/**
 * @brief s_context_callback_started
 * @details GlobalDB context started
 * @param a_context
 * @param a_arg
 */
static void s_context_callback_started( dap_context_t * a_context, void *a_arg)
{
    // Init its own queue
    s_context_global_db->queue_io = dap_context_create_queue(a_context, s_queue_io_callback);

    // Create arrays of inputs for connection with workers and proc threads
    s_context_global_db->queue_worker_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof(dap_events_socket_t*) *
                                                                dap_events_thread_get_count() );
    s_context_global_db->queue_worker_ch_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof(dap_events_socket_t*) *
                                                                dap_events_thread_get_count() );
    s_context_global_db->queue_worker_callback_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof(dap_events_socket_t*) *
                                                                dap_events_thread_get_count() );

    s_context_global_db->queue_proc_thread_callback_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof(dap_events_socket_t*) *
                                                                dap_events_thread_get_count() );

    // Fullful arrays with queue inputs
    for (uint32_t i = 0; i < dap_events_thread_get_count(); i++){
        dap_worker_t * l_worker = dap_events_worker_get(i);
        dap_stream_worker_t * l_stream_worker = DAP_STREAM_WORKER(l_worker);
        dap_proc_thread_t *l_proc_thread = dap_proc_thread_get(i);
        assert(l_worker);
        assert(l_proc_thread);

        // Input for I/O operations on worker
        s_context_global_db->queue_worker_io_input[i] =
                dap_events_socket_queue_ptr_create_input( l_worker->queue_es_io);
        dap_context_add( a_context, s_context_global_db->queue_worker_io_input[i]);

        // Input for ch I/O operations on worker
        s_context_global_db->queue_worker_ch_io_input[i] =
                dap_events_socket_queue_ptr_create_input( l_stream_worker->queue_ch_io );
        dap_context_add( a_context, s_context_global_db->queue_worker_ch_io_input[i]);

        // Input for callback queue on worker
        s_context_global_db->queue_worker_callback_input[i] =
                dap_events_socket_queue_ptr_create_input( l_worker->queue_callback);
        dap_context_add( a_context, s_context_global_db->queue_worker_callback_input[i]);

        // Input for callback queue on proc thread
        s_context_global_db->queue_proc_thread_callback_input[i] =
                dap_events_socket_queue_ptr_create_input( l_proc_thread->proc_queue->esocket );
        dap_context_add( a_context, s_context_global_db->queue_proc_thread_callback_input[i]);
    }
}


/**
 * @brief s_context_callback_stopped
 * @details Stop and destroy callback for GlobalDB context
 * @param a_context
 * @param a_arg
 */
static void s_context_callback_stopped( dap_context_t * a_context, void *a_arg)
{
    dap_events_socket_remove_and_delete_unsafe(s_context_global_db->queue_io, false);
    // Fullful arrays with queue inputs
    for (uint32_t i = 0; i < dap_events_thread_get_count(); i++){
        dap_events_socket_remove_and_delete_unsafe(s_context_global_db->queue_worker_io_input[i], true);
        dap_events_socket_remove_and_delete_unsafe(s_context_global_db->queue_worker_callback_input[i], true);
        dap_events_socket_remove_and_delete_unsafe(s_context_global_db->queue_proc_thread_callback_input[i], true);
    }
    DAP_DELETE(s_context_global_db->queue_worker_io_input);
    DAP_DELETE(s_context_global_db->queue_worker_callback_input);
    DAP_DELETE(s_context_global_db->queue_proc_thread_callback_input);
}




/**
 * @brief s_check_db_version
 * @return
 */
static int s_check_db_version()
{
    int l_ret;
    pthread_mutex_lock(&s_check_db_mutex);
    l_ret = dap_global_db_get(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version",s_check_db_version_callback_get, NULL);
    if (l_ret == 0){
        pthread_cond_wait(&s_check_db_cond, &s_check_db_mutex);
        l_ret = s_check_db_ret;
    }
    pthread_mutex_unlock(&s_check_db_mutex);
    return l_ret;
}

/**
 * @brief s_check_db_version_callback_get
 * @details Notify callback on reading GlobalDB version
 * @param a_errno
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_arg
 */
static void s_check_db_version_callback_get (dap_global_db_context_t * a_global_db_context, int a_errno, const char * a_group, const char * a_key,
                                             const void * a_value, const size_t a_value_len,
                                             dap_nanotime_t value_ts, bool a_is_pinned, void * a_arg)
{
    int res = 0;


    if(a_errno != 0){
        log_it(L_ERROR, "Can't process request for DB version, error code %d", a_errno);
        res = a_errno;
        goto lb_exit;
    }

    const char * l_value_str = (const char *) a_value;
    if(a_value_len>0 ){
        if(l_value_str[a_value_len-1]=='\0'){
            s_global_db_version = atoi(l_value_str);
        }
    }

    if( s_global_db_version < DAP_GLOBAL_DB_VERSION) {
        log_it(L_NOTICE, "GlobalDB version %u, but %u required. The current database will be recreated",
               s_global_db_version, DAP_GLOBAL_DB_VERSION);
        dap_global_db_deinit();
        // Database path
        const char *l_storage_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
        // Delete database
        if(dap_file_test(l_storage_path) || dap_dir_test(l_storage_path)) {
            // Backup filename: backup_global_db_ver.X_DATE_TIME.zip
            char now[255];
            time_t t = time(NULL);
            strftime(now, 200, "%y.%m.%d-%H_%M_%S", localtime(&t));
#ifdef DAP_BUILD_WITH_ZIP
            char *l_output_file_name = dap_strdup_printf("backup_%s_ver.%d_%s.zip", dap_path_get_basename(l_storage_path), l_gdb_version, now);
            char *l_output_file_path = dap_build_filename(l_storage_path, "../", l_output_file_name, NULL);
            // Create backup as ZIP file
            if(dap_zip_directory(l_storage_path, l_output_file_path)) {
#else
            char *l_output_file_name = dap_strdup_printf("backup_%s_ver.%d_%s.tar", dap_path_get_basename(s_storage_path), s_global_db_version, now);
            char *l_output_file_path = dap_build_filename(l_storage_path, "../", l_output_file_name, NULL);
            // Create backup as TAR file
            if(dap_tar_directory(l_storage_path, l_output_file_path)) {
#endif
                // Delete database file or directory
                dap_rm_rf(l_storage_path);
            }
            else {
                log_it(L_ERROR, "Can't backup GlobalDB version %d", s_global_db_version);
                res = -2;
                goto lb_exit;
            }
            DAP_DELETE(l_output_file_name);
            DAP_DELETE(l_output_file_path);
        }
        // Reinitialize database
        res = dap_global_db_init(NULL, NULL);
        // Save current db version
        if(!res) {
            s_global_db_version = DAP_GLOBAL_DB_VERSION;
            dap_global_db_set(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version", &s_global_db_version, sizeof(uint16_t),false,
                              s_check_db_version_callback_set, NULL);
            return; // In this case the condition broadcast should happens in s_check_db_version_callback_set()
        }
    } else if(s_global_db_version > DAP_GLOBAL_DB_VERSION) {
        log_it(L_ERROR, "GlobalDB version %d is newer than supported version %d", s_global_db_version, DAP_GLOBAL_DB_VERSION);
        res = -1;
        goto lb_exit;
    }
    else {
        log_it(L_NOTICE, "GlobalDB version %d", s_global_db_version);
    }
lb_exit:
    s_check_db_ret = res;
    pthread_mutex_lock(&s_check_db_mutex); //    To be sure thats we're on pthread_cond_wait() line
    pthread_cond_broadcast(&s_check_db_cond);
    pthread_mutex_unlock(&s_check_db_mutex); //  in calling thread
}

/**
 * @brief s_check_db_version_callback_set
 * @details GlobalDB version update callback
 * @param a_errno
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_arg
 */
static void s_check_db_version_callback_set (dap_global_db_context_t * a_global_db_context,int a_errno, const char * a_group, const char * a_key,
                                             const void * a_value, const size_t a_value_len,
                                             dap_nanotime_t value_ts, bool a_is_pinned, void * a_arg)
{
    int l_res = 0;
    if(a_errno != 0){
        log_it(L_ERROR, "Can't process request for DB version, error code %d", a_errno);
        l_res = a_errno;
        goto lb_exit;
    }

    log_it(L_NOTICE, "GlobalDB version updated to %d", s_global_db_version);

lb_exit:
    s_check_db_ret = l_res;
    pthread_mutex_lock(&s_check_db_mutex); //  in calling thread
    pthread_cond_broadcast(&s_check_db_cond);
    pthread_mutex_unlock(&s_check_db_mutex); //  in calling thread
}
