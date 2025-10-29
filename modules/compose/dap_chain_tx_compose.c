/*
 * Authors:
 * Roman Padenkov <roman.padenkov@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2025-2026
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
   */


#include "dap_common.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_tx_compose_callbacks.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_mempool_compose.h"
#include "dap_net.h"
#include "dap_app_cli.h"
#include "dap_json_rpc.h"
#include "dap_app_cli_net.h"
#include "dap_cli_server.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_node_client.h"
#include "dap_client_http.h"
#include "dap_http_status_code.h"
#include "dap_worker.h"
#include "dap_json.h"
#include "dap_rand.h"
#include "dap_http_status_code.h"
#include "dap_chain_wallet_shared.h"

#define LOG_TAG "dap_chain_tx_compose"

int dap_chain_tx_compose_init(void)
{
    log_it(L_NOTICE, "Initializing compose module");
    return dap_chain_tx_compose_callbacks_init();
}

void dap_chain_tx_compose_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing compose module");
    dap_chain_tx_compose_callbacks_deinit();
}

/**
 * @brief Universal compose function using registered service callbacks
 * @param a_config Compose configuration
 * @param a_srv_uid Service UID
 * @param a_service_params Service-specific parameters
 * @return Created transaction or NULL
 */
dap_chain_datum_tx_t* dap_chain_tx_compose_for_service(dap_chain_tx_compose_config_t *a_config,
                                                       uint64_t a_srv_uid, 
                                                       void *a_service_params)
{
    if (!a_config) {
        log_it(L_ERROR, "Invalid config parameter");
        return NULL;
    }
    
    dap_chain_tx_compose_callback_t l_callback = dap_chain_tx_compose_service_callback_get(a_srv_uid);
    
    if (!l_callback) {
        log_it(L_ERROR, "No compose callback registered for service %"DAP_UINT64_FORMAT_X, a_srv_uid);
        return NULL;
    }
    
    return l_callback(a_service_params, a_config);
}

dap_chain_tx_compose_config_t* dap_chain_tx_compose_config_init(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                 uint16_t a_port, const char *a_enc_cert_path)
{
    dap_return_val_if_pass(!a_net_id.raw || !a_net_name || !a_native_ticker || !a_url_str || !a_port, NULL);
    dap_chain_tx_compose_config_t *l_config = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_compose_config_t, NULL);
    l_config->net_id.uint64 = a_net_id.uint64;
    l_config->net_name = a_net_name;
    l_config->native_ticker = a_native_ticker;
    l_config->url_str = a_url_str;

    l_config->port = a_port;
    l_config->enc_cert_path = a_enc_cert_path;


    log_it_fl(L_DEBUG, "a_net_name: %s, a_url_str: %s, a_port: %d, a_enc_cert_path: %s", a_net_name, a_url_str, a_port, a_enc_cert_path ? a_enc_cert_path : "NULL");
    l_config->response_handler = dap_json_object_new();
    if (!l_config->response_handler) {
        DAP_DELETE(l_config);
        return NULL;
    }

    return l_config;
}

dap_json_t *dap_chain_tx_compose_config_return_response_handler(dap_chain_tx_compose_config_t *a_config)
{
    if (!a_config || !a_config->response_handler) {
        return NULL;
    }
    dap_json_t *l_responce_handler = a_config->response_handler;
    a_config->response_handler = NULL; // Prevent double free
    DAP_DELETE(a_config);
    return l_responce_handler;
}

static int s_compose_config_deinit(dap_chain_tx_compose_config_t *a_config) {
    if (!a_config) {
        return -1;
    }
    if (a_config->response_handler) {
        dap_json_object_free(a_config->response_handler);
        a_config->response_handler = NULL;
    }
    DAP_DELETE(a_config);
    return 0;
}

int dap_json_compose_error_add(dap_json_t *a_json_obj_reply, int a_code_error, const char *msg, ...)
{
    if (!a_json_obj_reply || !msg || !dap_json_is_object(a_json_obj_reply)) {
        return -1;
    }

    va_list args;
    va_start(args, msg);
    char *l_msg = dap_strdup_vprintf(msg, args);
    va_end(args);

    if (!l_msg) {
        return -1;
    }

    dap_json_t *l_json_arr_errors = NULL;
    if (!dap_json_object_get_ex(a_json_obj_reply, "errors", &l_json_arr_errors)) {
        l_json_arr_errors = dap_json_array_new();
        if (!l_json_arr_errors) {
            log_it(L_ERROR, "can't create errors array");
            DAP_DELETE(l_msg);
            return -1;
        }
        dap_json_object_add_array(a_json_obj_reply, "errors", l_json_arr_errors);
    }

    dap_json_t *l_obj_error = dap_json_object_new();
    if (!l_obj_error) {
        log_it(L_ERROR, "can't create error object");
        DAP_DELETE(l_msg);
        return -1;
    }

    dap_json_t *l_code = dap_json_object_new_int(a_code_error);
    dap_json_t *l_message = dap_json_object_new_string(l_msg);

    if (!l_code || !l_message) {
        log_it(L_ERROR, "Can't create code or message");
        dap_json_object_free(l_code);
        dap_json_object_free(l_message);
        dap_json_object_free(l_obj_error);
        DAP_DELETE(l_msg);
        return -1;
    }

    dap_json_object_add_object(l_obj_error, "code", l_code);
    dap_json_object_add_object(l_obj_error, "message", l_message);
    dap_json_array_add(l_json_arr_errors, l_obj_error);

    DAP_DELETE(l_msg);
    return 0;
}

int dap_chain_tx_compose_json_tsd_add(dap_json_t *json_tx, dap_json_t *json_add) {
    if (!json_tx || !json_add) {
        return -1;
    }

    dap_json_t *items_array;
    if (!dap_json_object_get_ex(json_tx, "items", &items_array)) {
        return -1;
    }

    if (!dap_json_is_array(items_array)) {
        return -1;
    }

    dap_json_array_add(items_array, json_add);
    return 0;
}

static dap_chain_wallet_t* dap_wallet_open_with_pass(const char *a_wallet_name, const char *a_wallets_path, const char *a_pass_str, dap_chain_tx_compose_config_t* a_config) {
    dap_return_val_if_pass(!a_wallet_name || !a_wallets_path || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_wallet_name: %s, a_wallets_path: %s, a_pass_str: %s, a_config: %p", a_wallet_name, a_wallets_path, a_pass_str, a_config);
    
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(a_wallet_name, a_wallets_path, NULL);
    if (!l_wallet) {
        if (access(a_wallets_path, F_OK) == 0) {
            if (!a_pass_str) {
                log_it(L_ERROR, "password required for wallet %s", a_wallet_name);
                dap_json_compose_error_add(a_config->response_handler, -134, "Password required for wallet %s", a_wallet_name);
                return NULL;
            }
            char l_file_name [MAX_PATH + 1] = "";
            snprintf(l_file_name, sizeof(l_file_name), "%s/%s%s", a_wallets_path, a_wallet_name, ".dwallet");

            l_wallet = dap_chain_wallet_open_file(l_file_name, a_pass_str, NULL);
            if (!l_wallet) {
                log_it(L_ERROR, "wrong password for wallet %s", a_wallet_name);
                dap_json_compose_error_add(a_config->response_handler, -134, "Wrong password for wallet %s", a_wallet_name);
                return NULL;
            }
        } else {
            log_it(L_ERROR, "wallet %s not found in the directory %s", a_wallet_name, a_wallets_path);
            dap_json_compose_error_add(a_config->response_handler, -136, "Wallet %s not found in the directory %s", a_wallet_name, a_wallets_path);
            return NULL;
        }
    }
    return l_wallet;
}
struct cmd_request {
#ifdef DAP_OS_WINDOWS
    CONDITION_VARIABLE wait_cond;
    CRITICAL_SECTION wait_crit_sec;
#else
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
#endif
    char* response;
    size_t response_size;
    int error_code;
};

static struct cmd_request* s_cmd_request_init()
{
    log_it_fl(L_DEBUG, "s_cmd_request_init");
    struct cmd_request *l_cmd_request = DAP_NEW_Z_RET_VAL_IF_FAIL(struct cmd_request, NULL);
#ifdef DAP_OS_WINDOWS
    InitializeCriticalSection(&l_cmd_request->wait_crit_sec);
    InitializeConditionVariable(&l_cmd_request->wait_cond);
#else
    pthread_mutex_init(&l_cmd_request->wait_mutex, NULL);
#ifdef DAP_OS_DARWIN
    pthread_cond_init(&l_cmd_request->wait_cond, NULL);
#else
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&l_cmd_request->wait_cond, &attr);
    pthread_condattr_destroy(&attr);
#endif
#endif
    return l_cmd_request;
}

void s_cmd_request_free(struct cmd_request *a_cmd_request)
{
    if (!a_cmd_request)
        return;

#ifdef DAP_OS_WINDOWS
    DeleteCriticalSection(&a_cmd_request->wait_crit_sec);
#else
    pthread_mutex_destroy(&a_cmd_request->wait_mutex);
    pthread_cond_destroy(&a_cmd_request->wait_cond);
#endif
    DAP_DEL_MULTY(a_cmd_request->response, a_cmd_request);
}

static void s_cmd_response_handler(void *a_response, size_t a_response_size, void *a_arg,
                                            dap_http_status_code_t http_status_code) {
    (void)http_status_code;
    struct cmd_request *l_cmd_request = (struct cmd_request *)a_arg;
    if (!l_cmd_request || !a_response)
        return;
#ifdef DAP_OS_WINDOWS
    EnterCriticalSection(&l_cmd_request->wait_crit_sec);
#else
    pthread_mutex_lock(&l_cmd_request->wait_mutex);
#endif
    l_cmd_request->response = DAP_DUP_SIZE(a_response, a_response_size);
    l_cmd_request->response_size = a_response_size;
#ifdef DAP_OS_WINDOWS
    WakeConditionVariable(&l_cmd_request->wait_cond);
    LeaveCriticalSection(&l_cmd_request->wait_crit_sec);
#else
    pthread_cond_signal(&l_cmd_request->wait_cond);
    pthread_mutex_unlock(&l_cmd_request->wait_mutex);
#endif
}

static void s_cmd_error_handler(int a_error_code, void *a_arg){
    struct cmd_request * l_cmd_request = (struct cmd_request *)a_arg;
    if (!l_cmd_request)
        return;
#ifdef DAP_OS_WINDOWS
    EnterCriticalSection(&l_cmd_request->wait_crit_sec);
    DAP_DELETE(l_cmd_request->response);
    l_cmd_request->response = NULL;
    l_cmd_request->error_code = a_error_code;
    WakeConditionVariable(&l_cmd_request->wait_cond);
    LeaveCriticalSection(&l_cmd_request->wait_crit_sec);
#else
    pthread_mutex_lock(&l_cmd_request->wait_mutex);
    DAP_DELETE(l_cmd_request->response);
    l_cmd_request->response = NULL;
    l_cmd_request->error_code = a_error_code;
    pthread_cond_signal(&l_cmd_request->wait_cond);
    pthread_mutex_unlock(&l_cmd_request->wait_mutex);
#endif
}

static int dap_chain_cmd_list_wait(struct cmd_request *a_cmd_request, int a_timeout_ms) {
    if (!a_cmd_request || a_timeout_ms <= 0)
        return -1;

#ifdef DAP_OS_WINDOWS
    EnterCriticalSection(&a_cmd_request->wait_crit_sec);
    if (a_cmd_request->response)
        return LeaveCriticalSection(&a_cmd_request->wait_crit_sec), 0;
    while (!a_cmd_request->response) {
        if (!SleepConditionVariableCS(&a_cmd_request->wait_cond, &a_cmd_request->wait_crit_sec, a_timeout_ms)) {
            a_cmd_request->error_code = GetLastError() == ERROR_TIMEOUT ? 1 : 2;
            break;
        }
    }
    LeaveCriticalSection(&a_cmd_request->wait_crit_sec);
    return a_cmd_request->error_code;     
#else
    pthread_mutex_lock(&a_cmd_request->wait_mutex);
    if(a_cmd_request->response) {
        pthread_mutex_unlock(&a_cmd_request->wait_mutex);
        return 0;
    }
    
    struct timespec l_cond_timeout;
#ifdef DAP_OS_DARWIN
    l_cond_timeout.tv_sec = a_timeout_ms / 1000;
    l_cond_timeout.tv_nsec = (a_timeout_ms % 1000) * 1000000;
#else
    if (clock_gettime(CLOCK_MONOTONIC, &l_cond_timeout) != 0) {
        pthread_mutex_unlock(&a_cmd_request->wait_mutex);
        return -1;
    }
    l_cond_timeout.tv_sec += a_timeout_ms / 1000;
    l_cond_timeout.tv_nsec += (a_timeout_ms % 1000) * 1000000;
    if (l_cond_timeout.tv_nsec >= 1000000000) {
        l_cond_timeout.tv_sec += l_cond_timeout.tv_nsec / 1000000000;
        l_cond_timeout.tv_nsec %= 1000000000;
    }
#endif
    
    int ret = 0;
    while (!a_cmd_request->response) {
        int cond_ret;
#ifdef DAP_OS_DARWIN
        cond_ret = pthread_cond_timedwait_relative_np(&a_cmd_request->wait_cond, 
                    &a_cmd_request->wait_mutex, &l_cond_timeout);
#else
        cond_ret = pthread_cond_timedwait(&a_cmd_request->wait_cond, 
                    &a_cmd_request->wait_mutex, &l_cond_timeout);
#endif
        if (cond_ret == ETIMEDOUT) {
            a_cmd_request->error_code = 1;
            ret = 1;
            break;
        } else if (cond_ret != 0) {
            a_cmd_request->error_code = 2;
            ret = 2;
            break;
        }
    }
    pthread_mutex_unlock(&a_cmd_request->wait_mutex);
    return ret;
#endif
}

static int s_cmd_request_get_response(struct cmd_request *a_cmd_request, dap_json_t **a_response_out, size_t *a_response_out_size)
{
    if (!a_cmd_request || !a_response_out || !a_response_out_size)
        return -1;

    int ret = 0;
    *a_response_out = NULL;
    *a_response_out_size = 0;

    if (a_cmd_request->error_code) {
        ret = -1;
    } else if (a_cmd_request->response && a_cmd_request->response_size > 0) {
        dap_json_tokener_error_t error;
        *a_response_out = dap_json_tokener_parse_verbose(a_cmd_request->response, &error);
        if (*a_response_out) {
            *a_response_out_size = a_cmd_request->response_size;
        } else {
            ret = -3;
        }
    } else {
        ret = -2;
    }
    return ret;
}


dap_json_t* dap_enc_request_command_to_rpc(const char *a_request, const char * a_url, uint16_t a_port, const char * a_cert_path) {
    if (!a_request || !a_url || !a_port) {
        return NULL;
    }

    dap_json_rpc_params_t * params = dap_json_rpc_params_create();
    char *l_cmd_str = dap_str_replace_char(l_cmd_str, ',', ';', false);
    dap_json_rpc_params_add_data(params, l_cmd_str, TYPE_PARAM_STRING);
    uint64_t l_id_response = dap_json_rpc_response_get_new_id();
    char ** l_cmd_arr_str = dap_strsplit(l_cmd_str, ";", -1);
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_creation(l_cmd_arr_str[0], params, l_id_response, dap_cli_server_get_version());
    dap_strfreev(l_cmd_arr_str);
    DAP_DEL_Z(l_cmd_str);

    //send request
    dap_json_t * l_response = NULL;
    dap_json_rpc_request_send(a_url, a_port, NULL, NULL, l_request, &l_response, a_cert_path);

    dap_json_rpc_request_free(l_request);
    
    return l_response;
}

typedef enum {
    DAP_COMPOSE_ERROR_NONE = 0,
    DAP_COMPOSE_ERROR_RESPONSE_NULL = -1,
    DAP_COMPOSE_ERROR_RESULT_NOT_FOUND = -2,
    DAP_COMPOSE_ERROR_REQUEST_INIT_FAILED = -3,
    DAP_COMPOSE_ERROR_REQUEST_TIMEOUT = -4,
    DAP_COMPOSE_ERROR_REQUEST_FAILED = -5
} dap_compose_error_t;

static dap_json_t *s_request_command_to_rpc(const char *a_request, dap_chain_tx_compose_config_t *a_config) {
    dap_return_val_if_pass(!a_request || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_request: %s, a_config: %p", a_request, a_config);

    dap_json_t *l_responce = NULL;
    size_t l_responce_size = 0;
    struct cmd_request *l_cmd_request = s_cmd_request_init();

    if (!l_cmd_request) {
        log_it(L_ERROR, "failed to initialize command request");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_INIT_FAILED, "Failed to initialize command request");
        return NULL;
    }

    dap_client_http_request(dap_worker_get_auto(),
                                a_config->url_str,
                                a_config->port,
                                "POST", "application/json",
                                NULL, a_request, strlen(a_request), NULL,
                                s_cmd_response_handler, s_cmd_error_handler,
                                l_cmd_request, NULL);

    int l_ret = dap_chain_cmd_list_wait(l_cmd_request, 60000);

    if (!l_ret) {
        if (s_cmd_request_get_response(l_cmd_request, &l_responce, &l_responce_size)) {
            log_it(L_ERROR, "failed to get response");
            dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "Response error code: %d", l_cmd_request->error_code);
            s_cmd_request_free(l_cmd_request);
            return NULL;
        }
    } else {
        log_it(L_ERROR, "request timed out");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_TIMEOUT, "Request timed out");
        s_cmd_request_free(l_cmd_request);
        return NULL;
    }

    s_cmd_request_free(l_cmd_request);
    return l_responce;
}

static dap_json_t *s_request_command_parse(dap_json_t *a_response, dap_chain_tx_compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config || !a_response, NULL);

    dap_json_t *l_result = NULL;
    if (!dap_json_object_get_ex(a_response, "result", &l_result)) {
        log_it(L_ERROR, "failed to get 'result' from response");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESULT_NOT_FOUND, "Failed to get 'result' from response");
        return NULL;
    }

    if (!dap_json_is_array(l_result) || dap_json_array_length(l_result) == 0) {
        return l_result;
    }

    dap_json_t *first_element = dap_json_array_get_idx(l_result, 0);
    if (!first_element) {
        return l_result;
    }

    dap_json_t *errors_array = NULL;
    if (dap_json_object_get_ex(first_element, "errors", &errors_array) &&
        dap_json_is_array(errors_array)) {

        int errors_len = dap_json_array_length(errors_array);
        for (int j = 0; j < errors_len; j++) {
            dap_json_t *error_obj = dap_json_array_get_idx(errors_array, j);
            if (!error_obj) continue;
            
            dap_json_t *error_code = NULL, *error_message = NULL;
            dap_json_compose_error_add(a_config->response_handler, 
                                        dap_json_object_get_int(error_code, "code"),
                                        dap_json_object_get_string(error_message, "message"));
        }
        log_it_fl(L_DEBUG, "errors found in the response");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "errors found in the response");
        return NULL;
    }

    if (l_result) {
        // Note: dap_json doesn't need explicit reference counting like json-c
    }
    return l_result;
}

static dap_json_t *dap_request_command_to_rpc(const char *a_request, dap_chain_tx_compose_config_t *a_config) {
    dap_return_val_if_pass(!a_request || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_request: %s, a_config: %p", a_request, a_config);


    dap_json_t *l_responce = a_config->enc_cert_path ? 
                            dap_enc_request_command_to_rpc(a_request, a_config->url_str, a_config->port, a_config->enc_cert_path) 
                            : s_request_command_to_rpc(a_request, a_config) ;
    if (!l_responce) {
        return NULL;
    }

    dap_json_t *l_result = s_request_command_parse(l_responce, a_config);
    dap_json_object_free(l_responce);
    return l_result;
}


dap_json_t *dap_request_command_to_rpc_with_params(dap_chain_tx_compose_config_t *a_config, const char *a_method, const char *msg, ...) {
    dap_return_val_if_pass(!a_config || !msg || !a_method, NULL);
    log_it_fl(L_DEBUG, "a_config: %p, a_method: %s, msg: %s", a_config, a_method, msg);

    va_list args;
    va_start(args, msg);
    char *l_msg = dap_strdup_vprintf(msg, args);
    va_end(args);

    if (!l_msg) {
        log_it(L_ERROR, "failed to create message");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "failed to create message");
        return NULL;
    }

    if (dap_strlen(a_method) * 2 + dap_strlen(l_msg) + 50 >= 512) {
        log_it(L_ERROR, "message is too long");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "message is too long");
        DAP_DELETE(l_msg);
        return NULL;
    }
    char data[512] = {0};
    int l_ret = 0;
    if (a_config->enc_cert_path) {
        l_ret = snprintf(data, sizeof(data),
                        "%s;%s",
                        a_method, l_msg);
    } else {
        l_ret = snprintf(data, sizeof(data),
                            "{\"method\": \"%s\",\"params\": [\"%s;%s\"],\"id\": \"1\"}",
                            a_method, a_method, l_msg);
    }

    DAP_FREE(l_msg);

    if (l_ret < 0 || l_ret >= (int)sizeof(data)) {
        log_it(L_ERROR, "failed to create data");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "failed to create data");
        return NULL;
    }

    return s_request_command_to_rpc(data, a_config);
}


static dap_chain_net_id_t *s_get_bridged_networks(uint16_t *a_bridget_count, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config, NULL);
    dap_json_t *l_json_net = dap_request_command_to_rpc_with_params(a_config, "net", "get;status;-net;%s", a_config->net_name);
    if (!l_json_net || !dap_json_is_array(l_json_net)) {
        log_it(L_ERROR, "can't get net status");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "can't get net status");
        return NULL;
    }
    dap_json_t *l_first_result = dap_json_array_get_idx(l_json_net, 0);
    if (!l_first_result || !dap_json_is_object(l_first_result)) {
        log_it(L_ERROR, "failed to get first result element");
        dap_json_compose_error_add(a_config->response_handler, -6, "failed to get first result element");
        dap_json_object_free(l_json_net);
        return NULL;
    }
    dap_json_t *l_status;
    if (!dap_json_object_get_ex(l_first_result, "status", &l_status)) {
        log_it(L_ERROR, "can't get status from json answer");
        dap_json_compose_error_add(a_config->response_handler, -6, "can't get status from json answer");
        dap_json_object_free(l_json_net);
        return NULL;
    }
    dap_json_t *l_bridget_arr;
    if (!dap_json_object_get_ex(l_status, "bridged_networks", &l_bridget_arr) || !dap_json_is_array(l_bridget_arr)) {
        log_it(L_DEBUG, "net %s has no any bridget networks", a_config->net_name);
        dap_json_object_free(l_json_net);
        if (a_bridget_count)
            *a_bridget_count = 0;
        return NULL;
    }
    uint16_t l_bridget_count = dap_json_array_length(l_bridget_arr);
    uint16_t l_bridget_count_total = 0;
    dap_chain_net_id_t *l_ret = DAP_NEW_Z_COUNT(dap_chain_net_id_t, l_bridget_count);
    for (uint16_t i = 0; i < l_bridget_count; ++i) {
        dap_json_t *l_curr_bridge = dap_json_array_get_idx(l_bridget_arr, i);
        const char *l_curr_bridge_id_str = dap_json_object_get_string(l_curr_bridge, "id");
        sscanf(l_curr_bridge_id_str,"0x%016"DAP_UINT64_FORMAT_x, &(l_ret + i)->uint64);
        ++l_bridget_count_total;
    }
    if (a_bridget_count)
        *a_bridget_count = l_bridget_count_total;
    if (!l_bridget_count_total)
        DAP_DEL_Z(l_ret);
    return l_ret;
}

static bool s_chain_net_is_bridged(dap_chain_addr_t *l_addr, size_t a_addr_count, dap_chain_tx_compose_config_t *a_config)
{
    // bridge check
    uint16_t l_bridget_count = 0;
    dap_chain_net_id_t *l_bridged_nets = s_get_bridged_networks(&l_bridget_count, a_config);
    // check each addr, if any fail - all tx fail
    for (uint32_t i = 0; i < a_addr_count; ++i) {
        bool l_bridged = !l_addr[i].net_id.uint64 || l_addr[i].net_id.uint64 == a_config->net_id.uint64;  // with burn addr all nets bridget
        for (uint32_t j = 0; !l_bridged && j < l_bridget_count; ++j) {
            l_bridged |= l_bridged_nets[j].uint64 == l_addr[i].net_id.uint64;
        }
        if (!l_bridged) {
            DAP_DELETE(l_bridged_nets);
            return false;
        }
    }
    DAP_DELETE(l_bridged_nets);
    return true;
}

bool dap_chain_tx_compose_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **a_addr_fee, dap_chain_tx_compose_config_t *a_config) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    *l_addr_fee = DAP_NEW_Z(dap_chain_addr_t);
    randombytes(*l_addr_fee, sizeof(dap_chain_addr_t));
    a_net_fee->_lo.b = rand() % 500;
#else
    if (!a_net_fee || !a_addr_fee || !a_config || !a_config->net_name) {
        return false;
    }
    *a_addr_fee = NULL;

    dap_json_t *l_json_get_fee = dap_request_command_to_rpc_with_params(a_config, "net", "get;fee;-net;%s", a_config->net_name);
    if (!l_json_get_fee) {
        log_it(L_ERROR, "failed to get fee");
        dap_json_compose_error_add(a_config->response_handler, -5, "failed to get fee");
        return false;
    }

    dap_json_t *l_first_result = dap_json_array_get_idx(l_json_get_fee, 0);
    if (!l_first_result || !dap_json_is_object(l_first_result)) {
        log_it(L_ERROR, "failed to get first result");
        dap_json_compose_error_add(a_config->response_handler, -6, "failed to get first result");
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    dap_json_t *l_fees = NULL;
    dap_json_object_get_ex(l_first_result, "fees", &l_fees);
    if (!l_fees || 
        !dap_json_is_object(l_fees)) {
        log_it(L_ERROR, "failed to get fees");
        dap_json_compose_error_add(a_config->response_handler, -7, "failed to get fees");
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    dap_json_t *l_network = NULL;
    dap_json_object_get_ex(l_fees, "network", &l_network);
    if (!l_network || !dap_json_is_object(l_network)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    const char *l_balance_str = dap_json_object_get_string(l_network, "balance");
    if (!l_balance_str) {
        log_it(L_ERROR, "failed to get balance string");
        dap_json_compose_error_add(a_config->response_handler, -9, "failed to get balance string");
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    *a_net_fee = dap_chain_balance_scan(l_balance_str);

    if(IS_ZERO_256(*a_net_fee)) {
        log_it(L_INFO, "%s network feee is zero", a_config->net_name);
        json_object_put(l_json_get_fee);
        return false;
    }

    const char *l_addr_str = dap_json_object_get_string(l_network, "addr");
    if (!l_addr_str) {
        log_it(L_ERROR, "failed to get addr string");
        dap_json_compose_error_add(a_config->response_handler, -12, "failed to get addr string");
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    *a_addr_fee = dap_chain_addr_from_str(l_addr_str);
    dap_json_object_free(l_json_get_fee);

    if (!*a_addr_fee) {
        log_it(L_ERROR, "failed to get addr");
        dap_json_compose_error_add(a_config->response_handler, -13, "failed to get addr");
        return false;
    }
#endif
    return true;
}

bool dap_chain_tx_compose_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker,
                                         dap_json_t **l_outs, int *l_outputs_count, dap_chain_tx_compose_config_t *a_config) {
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s;-mempool_check", 
                                                                      dap_chain_addr_to_str(a_addr_from), a_token_ticker, a_config->net_name);
    if (!l_json_outs) {
        log_it(L_ERROR, "failed to get outs");
        dap_json_compose_error_add(a_config->response_handler, -14, "failed to get outs");
        return false;
    }

    if (!dap_json_is_array(l_json_outs)) {
        log_it(L_ERROR, "outs is not an array");
        dap_json_compose_error_add(a_config->response_handler, -15, "outs is not an array");
        dap_json_object_free(l_json_outs);
        return false;
    }

    if (!dap_json_array_length(l_json_outs)) {
        log_it(L_ERROR, "outs is empty");
        dap_json_compose_error_add(a_config->response_handler, -16, "outs is empty");
        dap_json_object_free(l_json_outs);
        return false;
    }

    dap_json_t *l_first_array = dap_json_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !dap_json_is_array(l_first_array)) {
        log_it(L_ERROR, "first array is not an array");
        dap_json_compose_error_add(a_config->response_handler, -17, "first array is not an array");
        dap_json_object_free(l_json_outs);
        return false;
    }

    dap_json_t *l_first_item = dap_json_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "first item is NULL");
        dap_json_compose_error_add(a_config->response_handler, -18, "first item is NULL");
        dap_json_object_free(l_json_outs);
        return false;
    }

    if (!dap_json_object_get_ex(l_first_item, "outs", l_outs) ||
        !dap_json_is_array(*l_outs)) {
        log_it(L_ERROR, "outs is not an array");
        dap_json_compose_error_add(a_config->response_handler, -19, "outs is not an array");
        dap_json_object_free(l_json_outs);
        return false;
    }

    *l_outputs_count = dap_json_array_length(*l_outs);
    // No need to call get() in dap_json
    dap_json_object_free(l_json_outs);
    return true;
}

typedef enum {
    TX_CREATE_COMPOSE_OK = 0,
    TX_CREATE_COMPOSE_MEMORY_ERROR = -1,
    TX_CREATE_COMPOSE_ADDR_ERROR = -2,
    TX_CREATE_COMPOSE_VALUE_ERROR = -3,
    TX_CREATE_COMPOSE_WALLET_ERROR = -4,
    TX_CREATE_COMPOSE_INVALID_PARAMS = -5,
    TX_CREATE_COMPOSE_FEE_ERROR = -6,
    TX_CREATE_COMPOSE_FUNDS_ERROR = -7,
    TX_CREATE_COMPOSE_OUT_ERROR = -8,
    TX_CREATE_COMPOSE_OUT_COUNT_ERROR = -9,
    TX_CREATE_COMPOSE_IN_COND_ERROR = -10,
    TX_CREATE_COMPOSE_INVALID_CONFIG = -11
} tx_create_compose_error_t;

dap_json_t *dap_chain_tx_compose_tx_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, const char *a_token_ticker, const char *a_value_str, const char *l_time_unlock_str, const char *a_fee_str, 
                                    const char *a_addr_base58_to, dap_chain_addr_t *a_addr_from) {
    dap_return_val_if_pass(!a_net_name || !a_native_ticker || !a_url_str || !a_port || !a_addr_base58_to, NULL);
    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "failed to create compose config");
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, TX_CREATE_COMPOSE_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t *l_value = NULL;
    dap_time_t *l_time_unlock = NULL;
    uint256_t l_value_fee = {};
    dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;
    size_t l_time_el_count = 0;


    l_value_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_value_fee) && (a_fee_str && !dap_strcmp(a_fee_str, "0"))) {
        log_it(L_ERROR, "fee is zero");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "tx_create requires parameter '-fee' to be valid uint256");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_el_count = dap_str_symbol_count(a_value_str, ',') + 1;
    if (l_time_unlock_str)
        l_time_el_count = dap_str_symbol_count(l_time_unlock_str, ',') + 1;
    if (a_addr_base58_to)
        l_addr_el_count = dap_str_symbol_count(a_addr_base58_to, ',') + 1;
    else 
        l_addr_el_count = l_value_el_count;

    if (a_addr_base58_to && l_addr_el_count != l_value_el_count) {
        log_it(L_ERROR, "num of '-to_addr' and '-value' should be equal");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "num of '-to_addr' and '-value' should be equal");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (l_time_el_count && (l_time_el_count != l_value_el_count || l_time_el_count != l_addr_el_count)) {
        log_it(L_ERROR, "num of '-to_addr', '-value' and  '-lock_before' should be equal");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "num of '-to_addr', '-value' and  '-lock_before' should be equal");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        log_it(L_ERROR, "failed to allocate memory");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    char **l_value_array = dap_strsplit(a_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        log_it(L_ERROR, "failed to read '-to_addr' arg");
        DAP_DELETE(l_value);
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            log_it(L_ERROR, "value is zero");
            DAP_DEL_MULTY(l_value);
            dap_strfreev(l_value_array);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "tx_create requires parameter '-value' to be valid uint256 value");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }
    dap_strfreev(l_value_array);

    if (l_time_unlock_str) {
        l_time_unlock = DAP_NEW_Z_COUNT(dap_time_t, l_value_el_count);
        if (!l_time_unlock) {
            log_it(L_ERROR, "failed to allocate memory for time unlock");
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        char **l_time_unlock_array = dap_strsplit(l_time_unlock_str, ",", l_value_el_count);
        if (!l_time_unlock_array) {
            DAP_DELETE(l_time_unlock);
            log_it(L_ERROR, "failed to read time unlock array");
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-lock_before' arg");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        for (size_t i = 0; i < l_value_el_count; ++i) {
            if (l_time_unlock_array[i] && !dap_strcmp(l_time_unlock_array[i], "0")) {
                l_time_unlock[i] = 0;
                continue;
            }
            l_time_unlock[i] = dap_time_from_str_rfc822(l_time_unlock_array[i]);
            if (!l_time_unlock[i]) {
                log_it(L_ERROR, "wrong time format for parameter -lock_before");
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Wrong time format. Parameter -lock_before must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +0300\"");
                DAP_DEL_MULTY(l_time_unlock, l_value);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        dap_strfreev(l_time_unlock_array);
    }

    if (a_addr_base58_to) {
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            DAP_DELETE(l_value);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        char **l_addr_base58_to_array = dap_strsplit(a_addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value, l_time_unlock);
            log_it(L_ERROR, "failed to read '-to_addr' arg");
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                log_it(L_ERROR, "destination address is invalid");
                for (size_t j = 0; j < i; ++j) {
                    DAP_DELETE(l_addr_to[j]);
                }
                DAP_DEL_MULTY(l_addr_to, l_value);
                dap_strfreev(l_addr_base58_to_array);
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "destination address is invalid");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            // bridge check
            if (!s_chain_net_is_bridged(l_addr_to[i], 1, l_config)) {
                for (size_t j = 0; j < i; ++j) {
                    DAP_DELETE(l_addr_to[j]);
                }
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "destination source network is not bridget with recepient network");
                log_it(L_ERROR, "destination source network is not bridget with recepient network");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        dap_strfreev(l_addr_base58_to_array);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_tx_create( a_addr_from, l_addr_to, a_token_ticker, l_value, l_time_unlock, l_value_fee, l_addr_el_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    DAP_DEL_MULTY(l_addr_to, l_value);
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_tx_create(dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char *a_token_ticker, uint256_t *a_value, dap_time_t *a_time_unlock, uint256_t a_value_fee, size_t a_tx_num, dap_chain_tx_compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!a_config) {
        return NULL;
    }
    if (!a_addr_from || !a_token_ticker || !a_value) {
        log_it(L_ERROR, "invalid parameters");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters");
        return NULL;
    }

    if (dap_chain_addr_check_sum(a_addr_from)) {
        log_it(L_ERROR, "invalid source address");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid source address");
        return NULL;
    }

    for (size_t i = 0; i < a_tx_num; ++i) {
        if (a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) {
            log_it(L_ERROR, "invalid destination address");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid destination address");
            return NULL;
        }
        if (IS_ZERO_256(a_value[i])) {
            log_it(L_ERROR, "invalid value");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "Invalid value");
            return NULL;
        }
    }
#endif
    const char *l_native_ticker = a_config->native_ticker;

    bool l_single_channel = !dap_strcmp(a_token_ticker, l_native_ticker);

    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_total = {}, l_total_fee = {}, l_fee_transfer = {};
    for (size_t i = 0; i < a_tx_num; ++i) {
        SUM_256_256(l_value_total, a_value[i], &l_value_total);
    }
    uint256_t l_value_need = l_value_total;

    dap_list_t *l_list_fee_out = NULL;
    uint256_t l_net_fee = {};
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    if (l_net_fee_used) {
        SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    }

    dap_json_t *l_native_outs = NULL;
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
    int l_native_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "failed to get wallet outs and count");
        dap_json_compose_error_add(a_config->response_handler, -21, "failed to get wallet outs and count");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }
    if (l_single_channel) {
        l_native_outs = l_outs;
        l_native_outputs_count = l_outputs_count;
    } else {
        if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_addr_from, l_native_ticker, &l_native_outs, &l_native_outputs_count, a_config)) {
            log_it(L_ERROR, "failed to get native outs and count");
            dap_json_compose_error_add(a_config->response_handler, -22, "failed to get native outs and count");
            dap_json_object_free(l_outs);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
    }
#endif

    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_native_outs, l_native_outputs_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer, false);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "failed to get fee outs");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
            dap_json_object_free(l_outs);
            dap_json_object_free(l_native_outs);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer, false);
    
    dap_json_object_free(l_outs);
    if (!l_single_channel)
        dap_json_object_free(l_native_outs);
    
    if (!l_list_used_out) {
        log_it(L_ERROR, "failed to get used outs");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        if (l_list_fee_out)
            dap_list_free_full(l_list_fee_out, NULL);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
        dap_list_free_full(l_list_used_out, NULL);
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
#endif
            dap_list_free_full(l_list_fee_out, NULL);
        }

    }
    if (a_tx_num > 1) {
        uint32_t l_tx_num = a_tx_num;
        dap_chain_tx_tsd_t *l_out_count = dap_chain_datum_tx_item_tsd_create(&l_tx_num, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        dap_chain_datum_tx_add_item(&l_tx, l_out_count);
        DAP_DELETE(l_out_count);
    }
    
    if (l_single_channel) { // add 'out' items
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], l_native_ticker, a_time_unlock ? a_time_unlock[i] : 0) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out' item");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
                SUM_256_256(l_value_pack, a_value[i], &l_value_pack);
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add network 'fee' item");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator's 'fee' item");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                log_it(L_ERROR, "failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
    } else { // add 'out_ext' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker, a_time_unlock ? a_time_unlock[i] : 0) != 1) {
                log_it(L_ERROR, "failed to add 'out_ext' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out_ext' item");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_total, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, a_token_ticker) != 1) {
                log_it(L_ERROR, "failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "failed to add network 'fee' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add network 'fee' item");
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                log_it(L_ERROR, "failed to add validator's 'fee' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator's 'fee' item");
                return NULL;
            }
        }
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                log_it(L_ERROR, "failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
    }
    return l_tx;
}

dap_json_t *dap_chain_tx_compose_get_remote_tx_outs(const char *a_token_ticker,  dap_chain_addr_t *a_addr, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_token_ticker || !a_addr || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_token_ticker: %s, a_addr: %s, a_config: %p",
    a_token_ticker, dap_chain_addr_to_str(a_addr), a_config);

    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s;-mempool_check", 
                                                                      dap_chain_addr_to_str(a_addr), a_token_ticker, a_config->net_name);
    if (!l_json_outs) {
        log_it(L_ERROR, "failed to get response from RPC request");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Failed to get response from RPC request");
        return NULL;
    }

    if (!dap_json_is_array(l_json_outs)) {
        log_it(L_ERROR, "Response is not an array");
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    if (dap_json_array_length(l_json_outs) == 0) {
        log_it(L_ERROR, "Response is empty");
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is empty");
        return NULL;
    }

    dap_json_t *l_first_array = dap_json_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !dap_json_is_array(l_first_array)) {
        log_it(L_ERROR, "Response is not an array");
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    dap_json_t *l_first_item = dap_json_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "Response is not an array");
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    dap_json_t *l_outs = NULL;
    if (!dap_json_object_get_ex(l_first_item, "outs", &l_outs) ||
        !dap_json_is_array(l_outs)) {
        log_it(L_ERROR, "Response is not an array");
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }
    // No need to call get() in dap_json
    dap_json_object_free(l_json_outs);
    return l_outs;
}

uint256_t dap_chain_tx_compose_get_balance_from_json(dap_json_t *l_json_outs, const char *a_token_sell) {
    uint256_t l_value = {};
    if (l_json_outs && dap_json_is_array(l_json_outs)) {
        for (size_t i = 0; i < dap_json_array_length(l_json_outs); i++) {
            dap_json_t *outer_array = dap_json_array_get_idx(l_json_outs, i);
            if (dap_json_is_array(outer_array)) {
                for (size_t j = 0; j < dap_json_array_length(outer_array); j++) {
                    dap_json_t *addr_obj = dap_json_array_get_idx(outer_array, j);
                    if (dap_json_is_object(addr_obj)) {
                        dap_json_t *tokens = NULL;
                        dap_json_object_get_ex(addr_obj, "tokens", &tokens);
                        if (tokens && dap_json_is_array(tokens)) {
                            for (size_t k = 0; k < dap_json_array_length(tokens); k++) {
                                dap_json_t *token_obj = dap_json_array_get_idx(tokens, k);
                                dap_json_t *token = NULL;
                                dap_json_object_get_ex(token_obj, "token", &token);
                                if (token && dap_json_is_object(token)) {
                                    dap_json_t *ticker = NULL;
                                    dap_json_object_get_ex(token, "ticker", &ticker);
                                    if (ticker && dap_json_is_string(ticker)) {
                                        const char *ticker_str = dap_json_get_string(ticker);
                                        if (strcmp(ticker_str, a_token_sell) == 0) {
                                            dap_json_t *datoshi = NULL;
                                            dap_json_object_get_ex(token_obj, "datoshi", &datoshi);
                                            if (datoshi && dap_json_is_string(datoshi)) {
                                                const char *datoshi_str = dap_json_get_string(datoshi);
                                                l_value = dap_uint256_scan_uninteger(datoshi_str);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return l_value;
}

bool dap_chain_tx_compose_check_token_in_ledger(dap_json_t *l_json_coins, const char *a_token) {
    if (dap_json_is_array(l_json_coins)) {
        for (size_t i = 0; i < dap_json_array_length(l_json_coins); i++) {
            dap_json_t *token_array = dap_json_array_get_idx(l_json_coins, i);
            if (dap_json_is_array(token_array)) {
                for (size_t j = 0; j < dap_json_array_length(token_array); j++) {
                    dap_json_t *token_obj = dap_json_array_get_idx(token_array, j);
                    dap_json_t *token_name = NULL;
                    dap_json_object_get_ex(token_obj, "token_name", &token_name);
                    if (token_name && dap_json_is_string(token_name)) {
                        const char *token_name_str = dap_json_get_string(token_name);
                        if (strcmp(token_name_str, a_token) == 0) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}


dap_json_t *dap_chain_tx_compose_tx_cond_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                        uint16_t a_port, const char *a_enc_cert_path, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr,
                                        const char *a_cert_str, const char *a_value_datoshi_str, const char *a_value_fee_str,
                                        const char *a_unit_str, const char *a_value_per_unit_max_str,
                                        const char *a_srv_uid_str, const char *a_pkey_hash_str)
{    
    dap_return_val_if_pass(!a_unit_str || !a_srv_uid_str || (!a_pkey_hash_str && !a_cert_str), NULL);
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, TX_COND_CREATE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }
    
    log_it_fl(L_DEBUG, "compose config initialized successfully");
    
    uint256_t l_value_datoshi = {};    
    uint256_t l_value_fee = {};
    uint256_t l_value_per_unit_max = {};
    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(a_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        log_it(L_ERROR, "can't find service UID %s", a_srv_uid_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_SERVICE_UID, "Can't find service UID %s", a_srv_uid_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)a_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        log_it(L_ERROR, "can't recognize unit '%s'", a_unit_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT, "Can't recognize unit '%s'. Unit must look like { B | SEC }\n", a_unit_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_datoshi = dap_chain_balance_scan(a_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        log_it(L_ERROR, "can't recognize value '%s' as a number", a_value_datoshi_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_datoshi_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_fee = dap_chain_balance_scan(a_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        log_it(L_ERROR, "can't recognize fee value '%s' as a number", a_value_fee_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_fee_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (a_value_per_unit_max_str)
        l_value_per_unit_max = dap_chain_balance_scan(a_value_per_unit_max_str);

    dap_hash_fast_t l_pkey_cond_hash = {};
    if (a_cert_str) {
        dap_cert_t *l_cert_cond = dap_cert_find_by_name(a_cert_str);
        if(!l_cert_cond) {
            log_it(L_ERROR, "can't find cert '%s'", a_cert_str);
            s_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND, "Can't find cert '%s'\n", a_cert_str);
            return s_compose_config_return_response_handler(l_config);
        }
        dap_cert_get_pkey_hash(l_cert_cond, &l_pkey_cond_hash);
    } else {
        dap_chain_hash_fast_from_str(a_pkey_hash_str, &l_pkey_cond_hash);
    }
    if (dap_hash_fast_is_blank(&l_pkey_cond_hash)) {
        log_it(L_ERROR, "can't calc pkey hash");
        s_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY, "Cert '%s' doesn't contain a valid public key\n", a_cert_str);
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_tx_cond_create(a_wallet_addr, &l_pkey_cond_hash, a_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_config);
    if (l_tx) {
        log_it_fl(L_DEBUG, "conditional transaction created successfully");
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create conditional transaction");
    }
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_tx_compose_datum_tx_cond_create(dap_chain_addr_t *a_wallet_addr, dap_hash_fast_t *a_pkey_cond_hash,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, dap_chain_tx_compose_config_t *a_config)
{
    // check valid param
    
    dap_return_val_if_pass(!a_config->net_name || !*a_config->net_name || !a_pkey_cond_hash || IS_ZERO_256(a_value) || !a_config->url_str || !*a_config->url_str || a_config->port == 0 || !a_wallet_addr, NULL);

    log_it_fl(L_DEBUG, "parameters validation passed");

    if (dap_strcmp(a_config->native_ticker, a_token_ticker)) {
        log_it(L_ERROR, "pay for service should be only in native token_ticker");
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NATIVE_TOKEN_REQUIRED, "Pay for service should be only in native token_ticker\n");
        return NULL;
    }
    uint256_t l_net_fee = {};
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = {};
    SUM_256_256(a_value, a_value_fee, &l_value_need);
    if (l_net_fee_used) {
        SUM_256_256(l_value_need, l_net_fee, &l_value_need);
    }
    // list of transaction with 'out' items
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_wallet_addr, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "failed to get remote wallet outputs");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }
#endif
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer, false);
    dap_json_object_free(l_outs);
    if(!l_list_used_out) {
        log_it(L_ERROR, "nothing to transfer (not enough funds)");
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS, "Nothing to transfer (not enough funds)\n");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
        dap_list_free_full(l_list_used_out, NULL);
    }
    // add 'out_cond' and 'out' items
    {
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_pkey_cond_hash, a_srv_uid, a_value, a_value_per_unit_max, a_unit, a_cond,
                a_cond_size) == 1) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_COND_OUTPUT_FAILED, "Cant add conditional output\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, a_token_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_COIN_BACK_FAILED, "Cant add coin back output\n");
                return NULL;
            }
        }
    }

    return l_tx;
}

typedef enum {
    CLI_TAKE_COMPOSE_OK = 0,
    RPC_DATA_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG = -1,
    RPC_DATA_COMPOSE_ERROR_INVALID_TRANSACTION_HASH = -2,
    RPC_DATA_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE = -3,
    RPC_DATA_COMPOSE_ERROR_NO_ITEMS_FOUND = -4,
    RPC_DATA_COMPOSE_ERROR_NO_TX_OUT_CONDITION = -5,
    RPC_DATA_COMPOSE_ERROR_TX_OUT_ALREADY_USED = -6,
    RPC_DATA_COMPOSE_ERROR_FAILED_GET_ITEMS_ARRAY = -7,
    RPC_DATA_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND = -8,
    RPC_DATA_COMPOSE_ERROR_INVALID_COINS_FORMAT = -9,
    RPC_DATA_COMPOSE_ERROR_INVALID_FEE_FORMAT = -10,
    RPC_DATA_COMPOSE_ERROR_UNABLE_TO_OPEN_WALLET = -11,
    RPC_DATA_COMPOSE_ERROR_OWNER_KEY_NOT_FOUND = -12,
    RPC_DATA_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED = -13,
    RPC_DATA_COMPOSE_ERROR_FAILED_TO_CREATE_TX = -14,
    RPC_DATA_COMPOSE_ERROR_NO_INFO_TX_OUT_USED = -15,
    RPC_DATA_COMPOSE_ERROR_TX_OUT_NOT_USED = -16,
} cli_take_compose_error_t;

dap_chain_datum_tx_t *dap_chain_tx_compose_get_datum_from_rpc(
    const char *a_tx_str, dap_chain_tx_compose_config_t *a_config,
    dap_chain_tx_out_cond_subtype_t a_cond_subtype,
    dap_chain_tx_out_cond_t **a_cond_tx, char **a_spent_by_hash, 
    char **a_token_ticker, int *a_out_idx, bool a_is_ledger)
{
    dap_json_t *l_raw_response = dap_request_command_to_rpc_with_params(a_config,
        a_is_ledger ? "ledger" : "mempool", 
        a_is_ledger ? "info;-hash;%s;-net;%s;-tx_to_json" : "dump;-datum;%s;-net;%s;-chain;main;-tx_to_json", 
        a_tx_str, a_config->net_name);
    if (!l_raw_response) {
        log_it(L_ERROR, "failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, RPC_DATA_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return NULL;
    }

    dap_json_t *l_responce = dap_json_array_get_idx(l_raw_response, 0);
    if (!l_responce) {
        log_it(L_ERROR, "No items found in response");
        dap_json_object_free(l_raw_response);
        dap_json_compose_error_add(a_config->response_handler, RPC_DATA_COMPOSE_ERROR_NO_ITEMS_FOUND, "No items found in response\n");
        return NULL;
    }
    // json_object_get(l_responce);
    dap_json_object_free(l_raw_response);
    dap_chain_datum_tx_t *l_datum = dap_chain_datum_tx_create();
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    if (dap_chain_tx_datum_from_json(l_responce, NULL, a_config->response_handler, &l_datum, &l_items_count, &l_items_ready) || l_items_count != l_items_ready) {
        log_it(L_ERROR, "failed to create transaction from json");
        dap_json_object_free(l_responce);
        dap_json_compose_error_add(a_config->response_handler, RPC_DATA_COMPOSE_ERROR_FAILED_TO_CREATE_TX, "Failed to create transaction from json\n");
        dap_chain_datum_tx_delete(l_datum);
        return NULL;
    }
    
    if (a_cond_tx) {
        uint8_t *l_cond_tx = NULL;
        size_t l_item_size = 0;
        int l_item_index = 0;
        int l_out_idx = 0;
        TX_ITEM_ITER_TX_TYPE(l_cond_tx, TX_ITEM_TYPE_OUT_ALL, l_item_size, l_item_index, l_datum) {
            if (*l_cond_tx == TX_ITEM_TYPE_OUT_COND && ((dap_chain_tx_out_cond_t *)l_cond_tx)->header.subtype == a_cond_subtype) {
                break;
            }
            ++l_out_idx;
        }
        if (!l_cond_tx) {
            log_it(L_ERROR, "No transaction output condition found");
            dap_json_object_free(l_responce);
            dap_json_compose_error_add(a_config->response_handler, RPC_DATA_COMPOSE_ERROR_NO_ITEMS_FOUND, "No transaction output condition found\n");
            dap_chain_datum_tx_delete(l_datum);
            return NULL;
        }
        if (a_spent_by_hash) {
            DAP_DEL_Z(*a_spent_by_hash);
            dap_json_t *l_spent_outs = dap_json_object_get_object(l_responce, "spent_outs");
            size_t l_spent_outs_count = l_spent_outs ? dap_json_array_length(l_spent_outs) : 0;
            for (size_t i = 0; i < l_spent_outs_count; i++) {
                dap_json_t *l_spent_out_json = dap_json_array_get_idx(l_spent_outs, i);
                if (dap_json_object_get_int(l_spent_out_json, "out_idx") == l_out_idx) {
                    const char *l_spent_by_tx = dap_json_object_get_string(l_spent_out_json, "spent_by_tx");
                    *a_spent_by_hash = dap_strdup(l_spent_by_tx);
                    break;
                }
            }
        }
        *a_cond_tx = l_cond_tx && l_item_size ? (dap_chain_tx_out_cond_t *)DAP_DUP_SIZE(l_cond_tx, l_item_size) : NULL;
        if (a_out_idx)
            *a_out_idx = l_out_idx;
    }

    if (a_token_ticker) {
        *a_token_ticker = dap_strdup(dap_json_object_get_string(l_responce, "token_ticker"));
        if (!(*a_token_ticker)) {
            log_it(L_ERROR, "Token ticker not found in response");
            dap_json_object_free(l_responce);
            dap_json_compose_error_add(a_config->response_handler, RPC_DATA_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND, "Token ticker not found in response\n");
            return NULL;
        }
    }
    dap_json_object_free(l_responce);
    return l_datum;
}

typedef enum {
    SRV_STAKE_ORDER_REMOVE_COMPOSE_OK = 0,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_WALLET_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_KEY_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_RPC_RESPONSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ADDR,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TAX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TS_CREATED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PRICE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_ENOUGH_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_SIGN,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_ITEMS_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TIMESTAMP,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_ALREADY_USED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER
} srv_stake_order_remove_compose_error_t;


static bool s_process_ledger_response(dap_chain_tx_out_cond_subtype_t a_cond_type, 
                                                dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_out_hash, dap_chain_tx_compose_config_t *a_config)
{
    *a_out_hash = *a_tx_hash;
    int l_prev_tx_count = 0;
    dap_chain_hash_fast_t l_hash = {};
    
    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                  dap_chain_hash_fast_to_str_static(a_tx_hash), a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "failed to get response from remote node");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return false;
    }
    
    dap_json_t *l_responce_array = dap_json_array_get_idx(response, 0);
    if (!l_responce_array) {
        log_it(L_ERROR, "can't get the first element from the response array");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Can't get the first element from the response array");
        dap_json_object_free(response);
        return false;
    }

    dap_json_t *items = dap_json_object_get_object(l_responce_array, "items");
    if (!items) {
        log_it(L_ERROR, "no items found in response");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: No items found in response");
        return false;
    }
    bool l_found = false;
    int items_count = dap_json_array_length(items);
    for (int i = 0; i < items_count; i++) {
        dap_json_t *item = dap_json_array_get_idx(items, i);
        const char *item_type = dap_json_object_get_string(item, "type");
        if (dap_strcmp(item_type, "out_cond") == 0) {
            const char *subtype = dap_json_object_get_string(item, "subtype");
            if (!dap_strcmp(subtype, dap_chain_tx_out_cond_subtype_to_str(a_cond_type))) {
                dap_chain_hash_fast_from_str(dap_json_object_get_string(item, "hash"), &l_hash);
                l_prev_tx_count++;
                l_found = true;
                break;
            }
        } else if (dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_cond") == 0 || dap_strcmp(item_type, "out_old") == 0) {
            l_prev_tx_count++;
        }
    }
    if (!l_found) {
        log_it(L_ERROR, "No items found in response");
        return false;
    }
    bool l_another_tx = false;
    dap_json_t *spent_outs = dap_json_object_get_object(l_responce_array, "spent_OUTs");
    if (spent_outs) {
        int spent_outs_count = dap_json_array_length(spent_outs);
        for (int i = 0; i < spent_outs_count; i++) {
            dap_json_t *spent_out = dap_json_array_get_idx(spent_outs, i);
            int out_index = dap_json_object_get_int(spent_out, "OUT - ");
            if (out_index == l_prev_tx_count) {
                dap_chain_hash_fast_from_str(dap_json_object_get_string(spent_out, "is_spent_by_tx"), &l_hash);
                l_another_tx = true;
                break;
            }
        }
    }
    if (l_another_tx) {
        *a_out_hash = l_hash;
        return true;
    }
    log_it_fl(L_DEBUG, "No items found in response");
    return false;
}

dap_chain_hash_fast_t dap_ledger_get_final_chain_tx_hash_compose(dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only, dap_chain_tx_compose_config_t *a_config)
{
    dap_chain_hash_fast_t l_hash = { };
    dap_return_val_if_pass(!a_tx_hash || dap_hash_fast_is_blank(a_tx_hash), l_hash);
    l_hash = *a_tx_hash;

    while(s_process_ledger_response( a_cond_type, a_tx_hash, &l_hash, a_config));

    return l_hash;
}


typedef enum {
    SHARED_FUNDS_HOLD_COMPOSE_ERR_CONFIG = -1,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE = -2,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_MEMORY = -3,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_HASH = -4,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_NETWORK = -5,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_WALLET = -6,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_BALANCE = -7,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_TX_CREATE = -8,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_TX_SIGN = -9,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_TX_SEND = -10
} dap_shared_funds_hold_compose_error_t;

dap_json_t *dap_chain_tx_compose_wallet_shared_hold(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char *a_token_str, const char *a_value_str, 
                                                    const char *a_fee_str, const char *a_signs_min_str, const char *a_pkeys_str, 
                                                    const char *a_tag_str)
{
    if (!a_net_name || !a_token_str) return NULL;

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SHARED_FUNDS_HOLD_COMPOSE_ERR_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Format -value <256 bit integer> and not equal zero");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Format -fee <256 bit integer> and not equal zer");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint32_t l_signs_min = atoi(a_signs_min_str);
    if (!l_signs_min) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Format -signs_minimum <32-bit unsigned integer>");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    size_t l_pkeys_str_size = strlen(a_pkeys_str);
    size_t l_hashes_count_max = l_pkeys_str_size / DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_chain_hash_fast_t)),
           l_hashes_count = 0;
    dap_chain_hash_fast_t *l_pkey_hashes = DAP_NEW_Z_COUNT(dap_chain_hash_fast_t, l_hashes_count_max);
    if (!l_pkey_hashes) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_MEMORY, c_error_memory_alloc);
        DAP_DEL_Z(l_pkey_hashes);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    char l_hash_str_buf[DAP_HASH_FAST_STR_SIZE];
    const char *l_token_ptr = a_pkeys_str;
    for (size_t i = 0; i < l_hashes_count_max; i++) {
        const char *l_cur_ptr = strchr(l_token_ptr, ',');
        if (!l_cur_ptr)
            l_cur_ptr = a_pkeys_str + l_pkeys_str_size;
        dap_strncpy(l_hash_str_buf, l_token_ptr, dap_min(DAP_HASH_FAST_STR_SIZE, l_cur_ptr - l_token_ptr));
        if (dap_chain_hash_fast_from_str(l_hash_str_buf, l_pkey_hashes + i)) {
            dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_hash_str_buf);
            DAP_DEL_Z(l_pkey_hashes);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        for (size_t j = 0; j < i; ++j) {
            if (!memcmp(l_pkey_hashes + j, l_pkey_hashes + i, sizeof(dap_chain_hash_fast_t))){
                dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Find pkey hash %s dublicate", l_hash_str_buf);
                DAP_DEL_Z(l_pkey_hashes);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        if (*l_cur_ptr == 0) {
            l_hashes_count = i + 1;
            break;
        }
        l_token_ptr = l_cur_ptr + 1;
    }

    if (!l_hashes_count) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_hash_str_buf);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (l_hashes_count < l_signs_min) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_VALUE, "Quantity of pkey_hashes %zu should not be less than signs_minimum (%zu)", l_hashes_count, l_signs_min);
        DAP_DEL_Z(l_pkey_hashes);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_wallet_shared_hold(a_owner_addr, a_token_str, l_value, l_fee, l_signs_min, l_pkey_hashes, l_hashes_count, a_tag_str, l_config);
    DAP_DEL_Z(l_pkey_hashes);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);

}


typedef enum {
    SHARED_FUNDS_HOLD_COMPOSE_ERR_OVERFLOW = -2,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_FUNDS = -3,
    SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE = -4
} shared_funds_hold_compose_err_t;

dap_chain_datum_tx_t * dap_chain_tx_compose_datum_wallet_shared_hold(dap_chain_addr_t *a_owner_addr, const char *a_token_ticker, uint256_t a_value, uint256_t a_fee, uint32_t a_signs_min, dap_hash_fast_t *a_pkey_hashes, size_t a_pkey_hashes_count, const char *a_tag_str, dap_chain_tx_compose_config_t *a_config)
{
    if (!a_owner_addr || !a_token_ticker ) return NULL;

    const char *l_native_ticker = a_config->native_ticker;
    bool l_share_native = !dap_strcmp(l_native_ticker, a_token_ticker);
    uint256_t l_value = a_value, l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address( &l_net_fee, &l_addr_fee, a_config);
    if ((l_net_fee_used && SUM_256_256(l_net_fee, a_fee, &l_fee_total) ) || (l_share_native && SUM_256_256(l_value, l_fee_total, &l_value))) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_OVERFLOW, "Integer overflow in TX composer");
        return NULL;
#endif
    }
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
    // list of transaction with 'out' items to sell
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
    l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_owner_addr, a_config);
    if (!l_outs_native) {
        return NULL;
    }

    if (l_share_native) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_chain_tx_compose_get_remote_tx_outs(a_token_ticker, a_owner_addr, a_config);
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_main_count = dap_json_array_length(l_outs_main);
#else
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
    int l_out_native_count = 0;
    int l_out_main_count = 0;
#endif

    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count, l_value, &l_value_transfer, false);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_FUNDS, "Not enough funds to transfer");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
        return NULL;
    }

    // add 'in' items to pay for share
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Can't compose the transaction input");
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
        return NULL;
    }
#endif
    dap_list_t *l_list_fee_out = NULL;
    if (!l_share_native) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count, l_fee_total, &l_fee_transfer, false);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_FUNDS, "Not enough funds to pay fee");
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Can't compose the fee transaction input");
            log_it(L_ERROR, "Can't compose the fee transaction input");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
    }

    // add 'out_cond' & 'out_ext' items
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_WALLET_SHARED_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
                                                l_uid, a_value, a_signs_min, a_pkey_hashes, a_pkey_hashes_count, a_tag_str);
    if (!l_tx_out) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Can't compose the transaction conditional output");
        log_it(L_ERROR, "Can't compose the transaction conditional output");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);

    
    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_value_transfer, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        int rc = l_share_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_value_back, l_native_ticker)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_value_back, a_token_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Cant add coin back output");
            log_it(L_ERROR, "Cant add coin back output");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Cant add net fee output");
            log_it(L_ERROR, "Cant add net fee output");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Cant add validator fee output");
        log_it(L_ERROR, "Cant add validator fee output");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
        return NULL;
    }

    if (!l_share_native) {
        uint256_t l_fee_back = {};
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_HOLD_COMPOSE_ERR_COMPOSE, "Cant add fee back output");
            log_it(L_ERROR, "Cant add fee back output");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
    }

    return l_tx;
}

typedef enum {
    SHARED_FUNDS_REFILL_COMPOSE_ERR_OK = 0,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_CONFIG,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_VALUE,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_NETWORK,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_OVERFLOW,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_FUNDS,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH,
    SHARED_FUNDS_REFILL_COMPOSE_ERR_MEMORY
} shared_funds_refill_compose_err_t;

typedef enum {
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_OK = 0,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_CONFIG = -1,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_PARAMS = -2,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_HASH = -3,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_NOT_FOUND = -4,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_FEE = -5,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_ADDR_VALUE_MISMATCH = -6,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_MEMORY = -7,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_VALUE = -8,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_OVERFLOW = -9,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INSUFFICIENT_FUNDS = -10,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE = -11,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_MISMATCH = -12,
    DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_NETWORK = -13
} dap_wallet_shared_funds_take_compose_error_t;

dap_json_t *dap_chain_tx_compose_wallet_shared_refill(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char *a_value_str, 
                                                    const char *a_fee_str, const char *a_tx_in_hash_str)
{
    if (!a_net_name || !a_owner_addr || !a_tx_in_hash_str || !a_value_str || !a_fee_str) return NULL;

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SHARED_FUNDS_REFILL_COMPOSE_ERR_CONFIG, "Can't create compose config");
        log_it(L_ERROR, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_VALUE, "Format -value <256 bit integer> and not equal zero");
        log_it(L_ERROR, "Format -value <256 bit integer> and not equal zero");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_VALUE, "Format -fee <256 bit integer> and not equal zero");
        log_it(L_ERROR, "Format -fee <256 bit integer> and not equal zero");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_in_hash;
    if (dap_chain_hash_fast_from_str(a_tx_in_hash_str, &l_tx_in_hash)) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_VALUE, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_json_t *l_json_response = dap_request_command_to_rpc_with_params(l_config, "ledger", "info;-hash;%s;-net;%s", a_tx_in_hash_str, l_config->net_name);
    if (!l_json_response) {
        dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_NETWORK, "Can't get ledger info");
        log_it(L_ERROR, "Can't get ledger info");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    // Check if response contains errors
    dap_json_t *l_first_item = dap_json_array_get_idx(l_json_response, 0);
    if (l_first_item) { 
        dap_json_t *l_errors_array = NULL;
        if (dap_json_object_get_ex(l_first_item, "errors", &l_errors_array) && 
            dap_json_is_array(l_errors_array) &&
            dap_json_array_length(l_errors_array) > 0) {
            dap_json_object_free(l_json_response);
            log_it(L_ERROR, "Ledger returned errors for transaction %s", a_tx_in_hash_str);
            dap_json_compose_error_add(l_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_NETWORK, "Ledger returned errors for transaction %s", a_tx_in_hash_str);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }

    dap_json_object_free(l_json_response);

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_wallet_shared_refill(a_owner_addr, l_value, l_fee, &l_tx_in_hash, NULL, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);

}

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_refill(dap_chain_addr_t *a_owner_addr, uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* a_tsd_items, dap_chain_tx_compose_config_t *a_config)
{
    if (!a_config || IS_ZERO_256(a_value) || IS_ZERO_256(a_fee)) return NULL;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    dap_json_t *l_json_ledger_info = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", dap_hash_fast_to_str_static(a_tx_in_hash), a_config->net_name);
    if (!l_json_ledger_info) {
        log_it(L_ERROR, "Can't get ledger info");
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_NETWORK, "Can't get ledger info");
        return NULL;
    }
    
    // Extract token ticker from JSON response
    char *l_tx_ticker = NULL;
    dap_json_t *l_first_item = dap_json_array_get_idx(l_json_ledger_info, 0);
    if (l_first_item) {
        const char *l_ticker_str = dap_json_object_get_string(l_first_item, "token_ticker");
        if (l_ticker_str) {
            l_tx_ticker = dap_strdup(l_ticker_str);
        }
    }
    dap_json_object_free(l_json_ledger_info);
    
    if (!l_tx_ticker) {
        log_it(L_ERROR, "Can't get token ticker");
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH, "Can't get token ticker");
        return NULL;
    }
#else
    char *l_tx_ticker = dap_strdup("tBUZ");
#endif
    const char *l_native_ticker = a_config->native_ticker;
    bool l_refill_native = !dap_strcmp(l_native_ticker, l_tx_ticker);
    uint256_t l_value = a_value, l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_chain_addr_t *l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address( &l_net_fee, &l_net_fee_addr, a_config);
    if ((l_net_fee_used && SUM_256_256(l_net_fee, a_fee, &l_fee_total) ) || (l_refill_native && SUM_256_256(l_value, l_fee_total, &l_value))) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_OVERFLOW, "Integer overflow in TX composer");
        log_it(L_ERROR, "Integer overflow in TX composer");
        DAP_DELETE(l_tx_ticker);
        return NULL;
#endif
    }

#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    // list of transaction with 'out' items to sell
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
    l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_owner_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get native outs");
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_FUNDS, "Can't get native outs");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    if (l_refill_native) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_chain_tx_compose_get_remote_tx_outs(l_tx_ticker, a_owner_addr, a_config);
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_main_count = dap_json_array_length(l_outs_main);
#else
    int l_out_native_count = 0;
    int l_out_main_count = 0;
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
#endif
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count, l_value, &l_value_transfer, false);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_FUNDS, "Not enough funds to transfer");
        dap_json_object_free(l_outs_native);
        if (!l_refill_native) {
            dap_json_object_free(l_outs_main);
        }
        log_it(L_ERROR, "Not enough funds to transfer");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    // add 'in' items to pay for share
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Can't compose the transaction input");
        dap_json_object_free(l_outs_native);
        if (!l_refill_native) {
            dap_json_object_free(l_outs_main);
        }
        log_it(L_ERROR, "Can't compose the transaction input");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }
    dap_list_t *l_list_fee_out = NULL;
    if (!l_refill_native) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count, l_fee_total, &l_fee_transfer, false);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            if (!l_refill_native) {
                dap_json_object_free(l_outs_main);
            }
            log_it(L_ERROR, "Not enough funds to pay fee");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Can't compose the fee transaction input");
            dap_json_object_free(l_outs_native);
            if (!l_refill_native) {
                dap_json_object_free(l_outs_main);
            }
            log_it(L_ERROR, "Can't compose the fee transaction input");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
    }
    dap_json_t *l_json_shared_info = dap_request_command_to_rpc_with_params(a_config, "wallet", "shared;info;-tx;%s;-net;%s", dap_hash_fast_to_str_static(a_tx_in_hash), a_config->net_name);
    if (!l_json_shared_info) {
        log_it(L_ERROR, "Can't get shared info");
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH, "Can't get shared info");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    char *l_final_tx_hash_str = NULL;
    l_first_item = dap_json_array_get_idx(l_json_shared_info, 0);
    if (l_first_item) {
        const char *l_temp_hash_str = dap_json_object_get_string(l_first_item, "tx_hash_final");
        if (l_temp_hash_str) {
            l_final_tx_hash_str = dap_strdup(l_temp_hash_str);
        }
    }
    dap_json_object_free(l_json_shared_info);
    
    if (!l_final_tx_hash_str) {
        log_it(L_ERROR, "Can't get final tx hash");
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH, "Can't get final tx hash");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    dap_hash_fast_t l_final_tx_hash;
    if (dap_chain_hash_fast_from_str(l_final_tx_hash_str, &l_final_tx_hash)) {
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", l_final_tx_hash_str);
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH, "Can't recognize %s as a hex or base58 format hash", l_final_tx_hash_str);
        DAP_DELETE(l_final_tx_hash_str);
        DAP_DELETE(l_tx_ticker);
        return NULL;    
    }
    
    // Keep l_final_tx_hash_str for the dap_chain_tx_compose_get_datum_from_rpc call
    dap_chain_tx_out_cond_t *l_cond_prev = NULL;
    char * l_token_ticker = NULL;
    int l_prev_cond_idx = 0;
    dap_chain_datum_tx_t *l_tx_in = dap_chain_tx_compose_get_datum_from_rpc(l_final_tx_hash_str, a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_cond_prev, NULL, &l_token_ticker, &l_prev_cond_idx, true);
    DAP_DELETE(l_token_ticker);
    
    DAP_DELETE(l_final_tx_hash_str);
    if (!l_tx_in) {
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    if (!l_cond_prev) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_TX_MISMATCH, "Requested conditional transaction requires conditional output");
        log_it(L_ERROR, "Requested conditional transaction requires conditional output");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }
#else
    dap_hash_fast_t l_final_tx_hash = {};
    dap_chain_srv_uid_t l_srv_uid = {};
    uint256_t l_value_out = {};
    randombytes(&l_final_tx_hash, sizeof(dap_hash_fast_t));
    randombytes(&l_srv_uid, sizeof(dap_chain_srv_uid_t));
    randombytes(&l_value_out, sizeof(uint256_t));
    int l_prev_cond_idx = rand();
    size_t l_owner_hashes_count = rand() % 10 + 1;
    size_t l_signs_min = rand() % l_owner_hashes_count + 1;
    dap_hash_fast_t *l_owner_hashes = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_hash_fast_t, l_owner_hashes_count * sizeof(dap_hash_fast_t), NULL);
    char *l_rand_tag = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(char, l_owner_hashes_count, NULL);
    dap_random_string_fill(l_rand_tag, l_owner_hashes_count);
    randombytes(l_owner_hashes, l_owner_hashes_count * sizeof(dap_hash_fast_t));
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_item_out_cond_create_wallet_shared(l_srv_uid, l_value_out, l_signs_min, l_owner_hashes, l_owner_hashes_count, l_rand_tag);
    DAP_DEL_MULTY(l_owner_hashes, l_rand_tag);
#endif
    // add 'in_cond' item
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_tx_hash, l_prev_cond_idx, -1) != 1) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Can't compose the transaction conditional input");
        log_it(L_ERROR, "Can't compose the transaction conditional input");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    uint256_t l_value_back = {};
    if(SUM_256_256(l_cond_prev->header.value, a_value, &l_value_back)) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_OVERFLOW, "Integer overflow in TX composer");
        log_it(L_ERROR, "Integer overflow in TX composer");
        DAP_DELETE(l_tx_ticker);
        return NULL;
#endif
    }

    dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
    if (!l_out_cond) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_MEMORY, "Can't allocate memory");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }
    l_out_cond->header.value = l_value_back;
    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond) < 0) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Cant add refill cond output");
        log_it(L_ERROR, "Cant add refill cond output");
        DAP_DELETE(l_out_cond);
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }
    DAP_DELETE(l_out_cond);

    // add track for refill from conditional value
    dap_chain_tx_tsd_t *l_refill_tsd = dap_chain_datum_tx_item_tsd_create(&a_value, DAP_CHAIN_WALLET_SHARED_TSD_REFILL, sizeof(uint256_t));
    if (dap_chain_datum_tx_add_item(&l_tx, l_refill_tsd) != 1) {
        DAP_DELETE(l_refill_tsd);
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Can't add TSD section item with withdraw value");
        log_it(L_ERROR, "Can't add TSD section item with withdraw value");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }
    DAP_DELETE(l_refill_tsd);

    //add other tsd if available
    for ( dap_list_t *l_tsd = a_tsd_items; l_tsd; l_tsd = l_tsd->next ) {
        if ( dap_chain_datum_tx_add_item(&l_tx, l_tsd->data) != 1 ) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Can't add custom TSD section item ");
            log_it(L_ERROR, "Can't add custom TSD section item ");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
    }

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        int rc = l_refill_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_value_back, l_native_ticker)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_value_back, l_tx_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Cant add coin back output");
            log_it(L_ERROR, "Cant add coin back output");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Cant add net fee output");
            log_it(L_ERROR, "Cant add net fee output");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Cant add validator fee output");
        log_it(L_ERROR, "Cant add validator fee output");
        DAP_DELETE(l_tx_ticker);
        return NULL;
    }

    if (!l_refill_native) {
        uint256_t l_fee_back = {};
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_json_compose_error_add(a_config->response_handler, SHARED_FUNDS_REFILL_COMPOSE_ERR_COMPOSE, "Cant add fee back output");
            log_it(L_ERROR, "Cant add fee back output");
            DAP_DELETE(l_tx_ticker);
            return NULL;
        }
    }

    DAP_DELETE(l_tx_ticker);
    return l_tx;
}



dap_json_t *dap_chain_tx_compose_wallet_shared_take(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                  uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char *a_tx_in_hash_str, const char *a_value_str, const char *a_fee_str, 
                                                  const char *a_to_addr_str)
{

    if (!a_net_name || !a_tx_in_hash_str || !a_value_str || !a_fee_str || !a_to_addr_str) return NULL;

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SHARED_FUNDS_REFILL_COMPOSE_ERR_CONFIG, "Can't create compose config");
        log_it(L_ERROR, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t *l_value = NULL;
    dap_chain_addr_t *l_to_addr = NULL;
    uint32_t
        l_addr_el_count = 0,  // not change type! use in batching TSD section
        l_value_el_count = 0;
    dap_list_t *l_tsd_list = NULL;


    dap_hash_fast_t l_tx_in_hash;
    if (dap_chain_hash_fast_from_str(a_tx_in_hash_str, &l_tx_in_hash)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_HASH, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }



    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_FEE, "Format -fee <256 bit integer> and not equal zero");
        log_it(L_ERROR, "Format -fee <256 bit integer> and not equal zero");
        s_compose_config_deinit(l_config);
        return l_config->response_handler;
    }

    l_addr_el_count = dap_chain_addr_from_str_array(a_to_addr_str, &l_to_addr);
    l_value_el_count = dap_str_symbol_count(a_value_str, ',') + 1;

    if (l_addr_el_count != l_value_el_count) {
        DAP_DELETE(l_to_addr);
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_ADDR_VALUE_MISMATCH, "num of '-to_addr' and '-value' should be equal");
        log_it(L_ERROR, "num of '-to_addr' and '-value' should be equal");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_MEMORY, c_error_memory_alloc);
        log_it(L_ERROR, "Can't allocate memory");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    char **l_value_array = dap_strsplit(a_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        DAP_DELETE(l_value);
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_PARAMS, "Can't read '-value' arg");
        log_it(L_ERROR, "Can't read '-value' arg");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            DAP_DELETE(l_value);
            dap_strfreev(l_value_array);
            dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_VALUE, "Format -value <256 bit integer> and not equal zero");
            log_it(L_ERROR, "Format -value <256 bit integer> and not equal zero");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }
    dap_strfreev(l_value_array);
    
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_wallet_shared_take(a_owner_addr, l_to_addr, l_value, l_value_el_count, l_fee, &l_tx_in_hash, NULL, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_take(dap_chain_addr_t *a_owner_addr, dap_chain_addr_t *a_to_addr, uint256_t *a_value, uint32_t a_addr_count, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* tsd_items, dap_chain_tx_compose_config_t *a_config)
{
    if (!a_to_addr || !a_value || !a_addr_count || !a_tx_in_hash || !a_config) return NULL;

#ifndef DAP_CHAIN_TX_COMPOSE_TEST

    dap_json_t *l_json_shared_info = dap_request_command_to_rpc_with_params(a_config, "wallet", "shared;info;-tx;%s;-net;%s", dap_hash_fast_to_str_static(a_tx_in_hash), a_config->net_name);
    if (!l_json_shared_info) {
        const char *l_hash_str = dap_hash_fast_to_str_static(a_tx_in_hash);
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't get shared info by hash %s", l_hash_str);
        log_it(L_ERROR, "Can't get shared info by hash %s", l_hash_str);
        return NULL;
    }

    char *l_final_tx_hash_str = NULL;
    dap_json_t *l_first_item = dap_json_array_get_idx(l_json_shared_info, 0);
    if (l_first_item) {
        const char *l_temp_hash_str = dap_json_object_get_string(l_first_item, "tx_hash_final");
        if (l_temp_hash_str) {
            l_final_tx_hash_str = dap_strdup(l_temp_hash_str);
        }
    }
    dap_json_object_free(l_json_shared_info);

    dap_chain_tx_out_cond_t *l_cond_prev = NULL;
    char *l_tx_ticker = NULL;
    char *l_spent_by_hash_str = NULL;
    int l_prev_cond_idx = 0;
    dap_hash_fast_t l_final_tx_hash = {};
    if (dap_chain_hash_fast_from_str(l_final_tx_hash_str, &l_final_tx_hash)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't recognize %s as a hex or base58 format hash", l_final_tx_hash_str);
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", l_final_tx_hash_str);
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_get_datum_from_rpc(l_final_tx_hash_str, a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_cond_prev, &l_spent_by_hash_str, &l_tx_ticker, &l_prev_cond_idx, true);
    if (!l_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't get shared info by hash %s", l_final_tx_hash_str);
        log_it(L_ERROR, "Can't get shared info by hash %s", l_final_tx_hash_str);
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker);
        return NULL;
    }
    dap_chain_datum_tx_delete(l_tx);
    l_tx = dap_chain_datum_tx_create();
    if (l_spent_by_hash_str) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Out cond wallet shared already spent by %s", l_spent_by_hash_str);
        log_it(L_ERROR, "Out cond wallet shared already spent by %s", l_spent_by_hash_str);
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker);
        return NULL;
    }

#else
    char *l_tx_ticker = dap_strdup("BUZ");
    dap_hash_fast_t l_final_tx_hash = {};
    dap_chain_srv_uid_t l_srv_uid = {};
    uint256_t l_value_out = {};
    randombytes(&l_final_tx_hash, sizeof(dap_hash_fast_t));
    randombytes(&l_srv_uid, sizeof(dap_chain_srv_uid_t));
    randombytes(&l_value_out, sizeof(uint256_t));
    int l_prev_cond_idx = rand();
    size_t l_owner_hashes_count = rand() % 10 + 1;
    size_t l_signs_min = rand() % l_owner_hashes_count + 1;
    dap_hash_fast_t *l_owner_hashes = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_hash_fast_t, l_owner_hashes_count * sizeof(dap_hash_fast_t), NULL);
    char *l_rand_tag = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(char, l_owner_hashes_count, NULL);
    dap_random_string_fill(l_rand_tag, l_owner_hashes_count);
    randombytes(l_owner_hashes, l_owner_hashes_count * sizeof(dap_hash_fast_t));
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_item_out_cond_create_wallet_shared(l_srv_uid, l_value_out, l_signs_min, l_owner_hashes, l_owner_hashes_count, l_rand_tag);
    char * l_final_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_final_tx_hash);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
#endif
    const char *l_native_ticker = a_config->native_ticker;

    bool l_taking_native = !dap_strcmp(l_native_ticker, l_tx_ticker);

    uint256_t l_value = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t *l_net_fee_addr = NULL;

    for (size_t i = 0; i < a_addr_count; ++i) {
        if(IS_ZERO_256(a_value[i])) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INVALID_VALUE, "Format -value <256 bit integer> and not equal zero");
            log_it(L_ERROR, "Format -value <256 bit integer> and not equal zero");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker);
            return NULL;
        }
        if (SUM_256_256(l_value, a_value[i], &l_value)) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_OVERFLOW, "Integer overflow in TX composer");
            log_it(L_ERROR, "Integer overflow in TX composer");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker);
            return NULL;
#endif
        }
    }

    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address( &l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used && SUM_256_256(l_net_fee, a_fee, &l_fee_total) ) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_OVERFLOW, "Integer overflow in TX composer");
        log_it(L_ERROR, "Integer overflow in TX composer");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
#endif
    }

    // list of transaction with 'out' items to sell
    dap_json_t *l_outs_native = NULL;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_owner_addr, a_config);
    if (!l_outs_native) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't get remote tx outs");
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
#else
    int l_out_native_count = 0;
#endif

    dap_list_t *l_list_fee_out = NULL;
    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count, l_fee_total, &l_fee_transfer, false);
    if (!l_list_fee_out) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Not enough funds to pay fee");
        log_it(L_ERROR, "Not enough funds to pay fee");
        dap_json_object_free(l_outs_native);
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't compose the fee transaction input");
        log_it(L_ERROR, "Can't compose the fee transaction input");
        dap_json_object_free(l_outs_native);
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }


    if (compare256(l_cond_prev->header.value, l_value) == -1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Conditional output of requested TX have not enough funds");
        log_it(L_ERROR, "Conditional output of requested TX have not enough funds");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
#endif

    // add 'in_cond' item
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_tx_hash, l_prev_cond_idx, -1) != 1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add conditional input");
        log_it(L_ERROR, "Cant add conditional input");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }

    // add 'out' or 'out_ext' item for emission
    for (size_t i = 0; i < a_addr_count; ++i) {
        int rc = l_taking_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, a_to_addr + i, a_value[i], l_native_ticker) :
            dap_chain_datum_tx_add_out_ext_item(&l_tx, a_to_addr + i, a_value[i], l_tx_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add tx output");
            log_it(L_ERROR, "Cant add tx output");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
            return NULL;
        }
    }

    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_cond_prev->header.value, l_value, &l_value_back);
    dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
    if (!l_out_cond) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_MEMORY, c_error_memory_alloc);
        log_it(L_ERROR, "Memory allocation error");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
    l_out_cond->header.value = l_value_back;
    
    if (-1 == dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond)) {
        DAP_DELETE(l_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add emission cond output");
        log_it(L_ERROR, "Can't add emission cond output");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
    DAP_DELETE(l_out_cond);

    if (a_addr_count > 1) {
        dap_chain_tx_tsd_t *l_addr_cnt_tsd = dap_chain_datum_tx_item_tsd_create(&a_addr_count, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        if (!l_addr_cnt_tsd || dap_chain_datum_tx_add_item(&l_tx, l_addr_cnt_tsd) != 1 ) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't add TSD section item with addr count");
            log_it(L_ERROR, "Can't add TSD section item with addr count");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
            return NULL;
        }
    }

    // add track for takeoff from conditional value
    dap_chain_tx_tsd_t *l_takeoff_tsd = dap_chain_datum_tx_item_tsd_create(&l_value, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF, sizeof(uint256_t));
    if (!l_takeoff_tsd || dap_chain_datum_tx_add_item(&l_tx, l_takeoff_tsd) != 1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't add TSD section item with withdraw value");
        log_it(L_ERROR, "Can't add TSD section item with withdraw value");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
        return NULL;
    }
    DAP_DELETE(l_takeoff_tsd);

    //add other tsd if available
    for ( dap_list_t *l_tsd = tsd_items; l_tsd; l_tsd = l_tsd->next ) {
        if ( dap_chain_datum_tx_add_item(&l_tx, l_tsd->data) != 1 ) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Can't add custom TSD section item ");
            log_it(L_ERROR, "Can't add custom TSD section item ");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
            return NULL;
        }
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add net fee output");
            log_it(L_ERROR, "Cant add net fee output");
            DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker, l_net_fee_addr);
            return NULL;
        }
    }
    DAP_DELETE(l_net_fee_addr);

    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add validator fee output");
        log_it(L_ERROR, "Cant add validator fee output");
        DAP_DEL_MULTY(l_final_tx_hash_str, l_tx_ticker);
        return NULL;
    }

    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, a_owner_addr, l_fee_back, l_native_ticker);
        if (rc != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_TAKE_COMPOSE_ERR_TX_COMPOSE, "Cant add fee back output");
            return NULL;
        }
    }
    return l_tx;
}



typedef enum {
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_OK = 0,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_CONFIG = -1,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_INVALID_PARAMS = -2,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_INVALID_HASH = -3,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_NOT_FOUND = -4,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_MEMORY = -5,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_COMPOSE = -6,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_TYPE = -7,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_MISMATCH = -8,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_OWNNER_MISMATCH = -9,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_NETWORK = -10,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_WALLET = -11,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_CERT = -12,
    DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_ENC_KEY = -13
} dap_wallet_shared_funds_sign_compose_error_t;

dap_json_t *dap_chain_tx_compose_wallet_shared_sign(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                  uint16_t a_port, const char *a_enc_cert_path, const char *a_tx_in_hash_str, const char *a_wallet_str, const char *a_wallets_path, const char *a_pass_str, const char *a_cert_str)
{
    dap_return_val_if_pass(!a_net_name || !a_tx_in_hash_str || (!a_wallet_str && !a_cert_str) || !a_url_str, NULL);

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_CONFIG, "Can't create compose config");
        log_it(L_ERROR, "Can't create compose config");
        return l_json_obj_ret;
    }

    if (a_wallet_str && a_cert_str) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_INVALID_PARAMS, "Can't specify both wallet and cert");
        log_it(L_ERROR, "Can't specify both wallet and cert");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_enc_key_t *l_enc_key = NULL;
    if (a_wallet_str) {
        dap_chain_wallet_t *l_wallet = dap_wallet_open_with_pass(a_wallet_str, a_wallets_path, a_pass_str, l_config);
        if (!l_wallet) {
            dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_WALLET, "Can't open wallet");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
    }

    if (a_cert_str) {
        dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_str);
        if (!l_cert) {
            dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_CERT, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        l_enc_key = dap_cert_get_keys_from_certs(&l_cert, 1, 0);
    }
    if (!l_enc_key) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_ENC_KEY, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_in_hash;
    if (dap_chain_hash_fast_from_str(a_tx_in_hash_str, &l_tx_in_hash)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_INVALID_HASH, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        log_it(L_ERROR, "Can't recognize %s as a hex or base58 format hash", a_tx_in_hash_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_wallet_shared_sign(a_tx_in_hash_str, l_enc_key, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_sign(const char *a_tx_in_hash_str, dap_enc_key_t *a_enc_key, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_tx_in_hash_str || !a_config, NULL);
    dap_chain_tx_out_cond_t *l_cond_out = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_get_datum_from_rpc(a_tx_in_hash_str, a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_cond_out, NULL, NULL, NULL, false);

    if (!l_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_NOT_FOUND, "Can't find transaction");
        log_it(L_ERROR, "Can't find transaction");
        return NULL;
    }

    if (!dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_TYPE, "Transaction is not a take");
        log_it(L_ERROR, "Transaction is not a take");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    bool l_is_owner = false;
    dap_hash_fast_t l_pkey_hash;
    dap_enc_key_get_pkey_hash(a_enc_key, &l_pkey_hash);
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, l_cond_out->tsd, l_cond_out->tsd_size) {
        if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                dap_hash_fast_compare(&l_pkey_hash, (dap_hash_fast_t *)l_tsd->data)) {
            l_is_owner = true;
            break;
        }
    }
    DAP_DELETE(l_cond_out);

    if (!l_is_owner) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_MISMATCH, "Signing pkey hash %s is not the owner", dap_hash_fast_to_str_static(&l_pkey_hash));
        log_it(L_ERROR, "Signing pkey hash %s is not the owner", dap_hash_fast_to_str_static(&l_pkey_hash));
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_WALLET_SHARED_FUNDS_SIGN_COMPOSE_ERR_TX_COMPOSE, "Can't add sign item");
        log_it(L_ERROR, "Can't add sign item");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    return l_tx;
}
