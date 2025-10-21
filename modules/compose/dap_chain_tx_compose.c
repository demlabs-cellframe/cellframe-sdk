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
#include "dap_worker.h"
#include "dap_json.h"
#include "dap_rand.h"
#include "dap_http_status_code.h"

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

dap_chain_tx_compose_config_t* dap_chain_tx_compose_config_init(const char *a_net_name, const char *a_url_str,
                                 uint16_t a_port, const char *a_cert_path) {
    if (!a_net_name) {
        return NULL;
    }
    dap_chain_tx_compose_config_t *l_config = DAP_NEW_Z(dap_chain_tx_compose_config_t);
    if (!l_config) {
        return NULL;
    }
    l_config->net_name = a_net_name;
    
    const char *l_url = a_url_str ? a_url_str : dap_chain_tx_compose_get_net_url(a_net_name);
    if (!l_url) {
        DAP_DELETE(l_config);
        return NULL;
    }
    l_config->url_str = l_url;

    uint16_t l_port = a_port ? a_port : dap_chain_tx_compose_get_net_port(a_net_name);
    if (!l_port) {
        DAP_DELETE(l_config);
        return NULL;
    }
    l_config->port = l_port;
    if (a_cert_path) {
        l_config->enc = true;
        l_config->cert_path = a_cert_path;
    } else {
        l_config->enc = false;
        l_config->cert_path = NULL;
    }

    l_config->response_handler = dap_json_object_new();
    if (!l_config->response_handler) {
        DAP_DELETE(l_config);
        return NULL;
    }

    return l_config;
}

dap_json_t* dap_chain_tx_compose_config_return_response_handler(dap_chain_tx_compose_config_t *a_config) {
    if (!a_config || !a_config->response_handler) {
        return NULL;
    }
    dap_json_t* l_response_handler = a_config->response_handler;
    a_config->response_handler = NULL; // Prevent double free
    DAP_DEL_Z(a_config);
    return l_response_handler;
}

static int s_compose_config_deinit(dap_chain_tx_compose_config_t *a_config) {
    if (!a_config) {
        return -1;
    }
    if (a_config->response_handler) {
        dap_json_object_free(a_config->response_handler);
        a_config->response_handler = NULL;
    }
    DAP_DEL_Z(a_config);
    return 0;
}

const char* dap_chain_tx_compose_get_net_url(const char* name) {
    // TODO: Get from network configuration, not hardcoded
    UNUSED(name);
    return "http://rpc.cellframe.net";
}

uint16_t dap_chain_tx_compose_get_net_port(const char* name) {
    // TODO: Get from network configuration, not hardcoded
    UNUSED(name);
    return 8081;
}

const char* dap_chain_tx_compose_get_native_ticker(const char* name) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    return "BUZ";
#endif
    if (!name) {
        return NULL;
    }
    // Use dap_chain_net API to get actual ticker
    dap_chain_net_t *l_net = dap_chain_net_by_name(name);
    return l_net ? l_net->pub.native_ticker : NULL;
}

dap_chain_net_id_t dap_chain_tx_compose_get_net_id(const char* name) {
    dap_chain_net_id_t empty_id = {.uint64 = 0};
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    randombytes(&empty_id, sizeof(empty_id));
#else
    if (!name) {
        return empty_id;
    }
    // Use dap_chain_net API to get actual net ID
    dap_chain_net_t *l_net = dap_chain_net_by_name(name);
    return l_net ? l_net->pub.id : empty_id;
#endif
    return empty_id;
}

int dap_json_compose_error_add(dap_json_t* a_json_obj_reply, int a_code_error, const char *msg, ...)
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
            DAP_DEL_Z(l_msg);
            return -1;
        }
        dap_json_object_add_array(a_json_obj_reply, "errors", l_json_arr_errors);
    }

    dap_json_t* l_obj_error = dap_json_object_new();
    if (!l_obj_error) {
        DAP_DEL_Z(l_msg);
        return -1;
    }

    dap_json_t *l_code = dap_json_object_new_int(a_code_error);
    dap_json_t *l_message = dap_json_object_new_string(l_msg);

    if (!l_code || !l_message) {
        if (l_code) dap_json_object_free(l_code);
        if (l_message) dap_json_object_free(l_message);
        dap_json_object_free(l_obj_error);
        DAP_DEL_Z(l_msg);
        return -1;
    }

    dap_json_object_add_object(l_obj_error, "code", l_code);
    dap_json_object_add_object(l_obj_error, "message", l_message);
    dap_json_array_add(l_json_arr_errors, l_obj_error);

    DAP_DEL_Z(l_msg);
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

static dap_chain_wallet_t* dap_wallet_open_with_pass(const char* a_wallet_name, const char* a_wallets_path, const char* a_pass_str, dap_chain_tx_compose_config_t* a_config) {
    if (!a_wallet_name || !a_wallets_path || !a_config){
        return NULL;
    }
    
    dap_chain_wallet_t* l_wallet = dap_chain_wallet_open(a_wallet_name, a_wallets_path, NULL);
    if (!l_wallet) {
        if (access(a_wallets_path, F_OK) == 0) {
            if (!a_pass_str) {
                dap_json_compose_error_add(a_config->response_handler, -134, "Password required for wallet %s", a_wallet_name);
                return NULL;
            }
            char l_file_name [MAX_PATH + 1] = "";
            snprintf(l_file_name, sizeof(l_file_name), "%s/%s%s", a_wallets_path, a_wallet_name, ".dwallet");

            l_wallet = dap_chain_wallet_open_file(l_file_name, a_pass_str, NULL);
            if (!l_wallet) {
                dap_json_compose_error_add(a_config->response_handler, -134, "Wrong password for wallet %s", a_wallet_name);
                return NULL;
            }
        } else {
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
    struct cmd_request *l_cmd_request = DAP_NEW_Z(struct cmd_request);
    if (!l_cmd_request)
        return NULL;
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
    DAP_DEL_Z(a_cmd_request->response);
    DAP_DELETE(a_cmd_request);
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
    DAP_DEL_Z(l_cmd_request->response);
    l_cmd_request->response = NULL;
    l_cmd_request->error_code = a_error_code;
    WakeConditionVariable(&l_cmd_request->wait_cond);
    LeaveCriticalSection(&l_cmd_request->wait_crit_sec);
#else
    pthread_mutex_lock(&l_cmd_request->wait_mutex);
    DAP_DEL_Z(l_cmd_request->response);
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
    char *l_cmd_str = dap_strdup(a_request);
    for(int i = 0; l_cmd_str[i] != '\0'; i++) {
        if (l_cmd_str[i] == ',')
            l_cmd_str[i] = ';'; 
    }
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

static dap_json_t* s_request_command_to_rpc(const char *request, dap_chain_tx_compose_config_t *a_config) {
    if (!request || !a_config) {
        return NULL;
    }

    dap_json_t *l_response = NULL;
    size_t l_response_size = 0;
    struct cmd_request *l_cmd_request = s_cmd_request_init();

    if (!l_cmd_request) {
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_INIT_FAILED, "Failed to initialize command request");
        return NULL;
    }

    dap_client_http_request(dap_worker_get_auto(),
                                a_config->url_str,
                                a_config->port,
                                "POST", "application/json",
                                NULL, request, strlen(request), NULL,
                                s_cmd_response_handler, s_cmd_error_handler,
                                l_cmd_request, NULL);

    int l_ret = dap_chain_cmd_list_wait(l_cmd_request, 60000);

    if (!l_ret) {
        if (s_cmd_request_get_response(l_cmd_request, &l_response, &l_response_size)) {
            dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "Response error code: %d", l_cmd_request->error_code);
            s_cmd_request_free(l_cmd_request);
            return NULL;
        }
    } else {
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_TIMEOUT, "Request timed out");
        s_cmd_request_free(l_cmd_request);
        return NULL;
    }

    s_cmd_request_free(l_cmd_request);
    return l_response;
}

static dap_json_t* s_request_command_parse(dap_json_t *l_response, dap_chain_tx_compose_config_t *a_config) {
    if (!l_response || !a_config) {
        if (a_config) {
            dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is NULL");
        }
        return NULL;
    }

    dap_json_t *l_result = NULL;
    if (!dap_json_object_get_ex(l_response, "result", &l_result)) {
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
            if (dap_json_object_get_ex(error_obj, "code", &error_code) &&
                dap_json_object_get_ex(error_obj, "message", &error_message)) {
                dap_json_compose_error_add(a_config->response_handler,
                                         dap_json_object_get_int(error_code, NULL),
                                         dap_json_object_get_string(error_message, NULL));
            }
        }
        return NULL;
    }

    if (l_result) {
        // Note: dap_json doesn't need explicit reference counting like json-c
    }
    return l_result;
}

dap_json_t* dap_request_command_to_rpc(const char *request, dap_chain_tx_compose_config_t *a_config) {
    if (!request || !a_config) {
        return NULL;
    }


    dap_json_t *l_response = a_config->enc ?
                            dap_enc_request_command_to_rpc(request, a_config->url_str, a_config->port, a_config->cert_path)
                            : s_request_command_to_rpc(request, a_config) ;
    if (!l_response) {
        return NULL;
    }

    dap_json_t *l_result = s_request_command_parse(l_response, a_config);
    dap_json_object_free(l_response);
    return l_result;
}


dap_json_t* dap_request_command_to_rpc_with_params(dap_chain_tx_compose_config_t *a_config, const char *a_method, const char *msg, ...) {
    if (!a_config || !msg || !a_method) {
        return NULL;
    }

    va_list args;
    va_start(args, msg);
    char *l_msg = dap_strdup_vprintf(msg, args);
    va_end(args);

    if (!l_msg) {
        return NULL;
    }

    if (dap_strlen(a_method) * 2 + dap_strlen(l_msg) + 50 >= 512) {
        DAP_FREE(l_msg);
        return NULL;
    }
    char data[512] = {0};
    int l_ret = 0;
    if (a_config->enc) {
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
        return NULL;
    }

    return dap_request_command_to_rpc(data, a_config);
}
    

bool dap_chain_tx_compose_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee, dap_chain_tx_compose_config_t *a_config) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    *l_addr_fee = DAP_NEW_Z(dap_chain_addr_t);
    randombytes(*l_addr_fee, sizeof(dap_chain_addr_t));
    a_net_fee->_lo.b = rand() % 500;
#else
    if (!a_net_fee || !l_addr_fee || !a_config || !a_config->net_name) {
        return false;
    }
    *l_addr_fee = NULL;

    dap_json_t *l_json_get_fee = dap_request_command_to_rpc_with_params(a_config, "net", "get;fee;-net;%s", a_config->net_name);
    if (!l_json_get_fee) {
        return false;
    }

    dap_json_t *l_first_result = dap_json_array_get_idx(l_json_get_fee, 0);
    if (!l_first_result || !dap_json_is_object(l_first_result)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    dap_json_t *l_fees = NULL;
    dap_json_object_get_ex(l_first_result, "fees", &l_fees);
    if (!l_fees || 
        !dap_json_is_object(l_fees)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    dap_json_t *l_network = NULL;
    dap_json_object_get_ex(l_fees, "network", &l_network);
    if (!l_network || 
        !dap_json_is_object(l_network)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    dap_json_t *l_balance = NULL;
    dap_json_object_get_ex(l_network, "balance", &l_balance);
    if (!l_balance || 
        !dap_json_is_string(l_balance)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    const char *l_balance_str = dap_json_get_string(l_balance);
    if (!l_balance_str) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    *a_net_fee = dap_chain_balance_scan(l_balance_str);

    dap_json_t *l_addr = NULL;
    dap_json_object_get_ex(l_network, "addr", &l_addr);
    if (!l_addr || 
        !dap_json_is_string(l_addr)) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    const char *l_addr_str = dap_json_get_string(l_addr);
    if (!l_addr_str) {
        dap_json_object_free(l_json_get_fee);
        return false;
    }

    *l_addr_fee = dap_chain_addr_from_str(l_addr_str);
    dap_json_object_free(l_json_get_fee);

    if (!*l_addr_fee) {
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
        return false;
    }

    if (!dap_json_is_array(l_json_outs)) {
        dap_json_object_free(l_json_outs);
        return false;
    }

    if (dap_json_array_length(l_json_outs) == 0) {
        dap_json_object_free(l_json_outs);
        return false;
    }

    dap_json_t *l_first_array = dap_json_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !dap_json_is_array(l_first_array)) {
        dap_json_object_free(l_json_outs);
        return false;
    }

    dap_json_t *l_first_item = dap_json_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        dap_json_object_free(l_json_outs);
        return false;
    }

    dap_json_object_get_ex(l_first_item, "outs", l_outs);
    if (!*l_outs ||
        !dap_json_is_array(*l_outs)) {
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
    TX_CREATE_COMPOSE_INVALID_CONFIG = -9,
    TX_CREATE_COMPOSE_TIME_UNLOCK_ERROR = -10
} tx_create_compose_error_t;

dap_json_t* dap_tx_create_compose(const char *l_net_str, const char *l_token_ticker, const char *l_value_str, const char *l_time_unlock_str,
                                  const char *l_fee_str, const char *addr_base58_to, 
                                  dap_chain_addr_t *l_addr_from, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {
    if (!l_net_str || !l_token_ticker || !l_value_str || !l_addr_from || !l_url_str) {
        return NULL;
    }
    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
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


    l_value_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_value_fee) && (l_fee_str && !dap_strcmp(l_fee_str, "0"))) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "tx_create requires parameter '-fee' to be valid uint256");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;
    if (l_time_unlock_str)
        l_time_el_count = dap_str_symbol_count(l_time_unlock_str, ',') + 1;
    if (addr_base58_to)
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
    else 
        l_addr_el_count = l_value_el_count;

    if (addr_base58_to && l_addr_el_count != l_value_el_count) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "num of '-to_addr' and '-value' should be equal");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (l_time_el_count && (l_time_el_count != l_value_el_count || l_time_el_count != l_addr_el_count)) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "num of '-to_addr', '-value' and  '-lock_before' should be equal");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        DAP_DELETE(l_value);
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
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
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        char **l_time_unlock_array = dap_strsplit(l_time_unlock_str, ",", l_value_el_count);
        if (!l_time_unlock_array) {
            DAP_DELETE(l_time_unlock);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        for (size_t i = 0; i < l_value_el_count; ++i) {
            if (l_time_unlock_array[i] && !dap_strcmp(l_time_unlock_array[i], "0")) {
                l_time_unlock[i] = 0;
                continue;
            }
            l_time_unlock[i] = dap_time_from_str_rfc822(l_time_unlock_array[i]);
            if (!l_time_unlock[i]) {
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Wrong time format. Parameter -lock_before must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +0300\"");
                DAP_DEL_MULTY(l_time_unlock, l_value);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        dap_strfreev(l_time_unlock_array);
    }

    if (addr_base58_to) {
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            DAP_DELETE(l_value);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value, l_time_unlock);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                for (size_t j = 0; j < i; ++j) {
                    DAP_DELETE(l_addr_to[j]);
                }
                DAP_DEL_MULTY(l_addr_to, l_value);
                dap_strfreev(l_addr_base58_to_array);
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "destination address is invalid");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        dap_strfreev(l_addr_base58_to_array);
    }

    for (size_t i = 0; l_addr_to && i < l_addr_el_count; ++i) {
        if (l_addr_to[i] && dap_chain_addr_compare(l_addr_to[i], l_addr_from)) {
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "The transaction cannot be directed to the same address as the source.");
            for (size_t j = 0; j < l_addr_el_count; ++j) {
                    DAP_DELETE(l_addr_to[j]);
            }
            DAP_DEL_MULTY(l_addr_to, l_value);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }

    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create_compose( l_addr_from, l_addr_to, l_token_ticker, l_value, l_time_unlock, l_value_fee, l_addr_el_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    DAP_DEL_MULTY(l_addr_to, l_value);
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

int dap_chain_datum_tx_add_out_without_addr(dap_chain_datum_tx_t **a_tx, uint256_t a_value) {
    if (IS_ZERO_256(a_value))
        return -1;
    
    dap_chain_tx_out_t *l_item = DAP_NEW_Z(dap_chain_tx_out_t);
    if (!l_item)
        return -1;
    
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    
    int res = dap_chain_datum_tx_add_item(a_tx, l_item);
    DAP_DELETE(l_item);
    
    return res;
}


int dap_chain_datum_tx_add_out_ext_item_without_addr(dap_chain_datum_tx_t **a_tx, uint256_t a_value, const char *a_token)
{
    if (!a_token || IS_ZERO_256(a_value))
        return -1;

    dap_chain_tx_out_ext_t *l_item = DAP_NEW_Z(dap_chain_tx_out_ext_t);
    if (!l_item)
        return -2;
    l_item->header.type = TX_ITEM_TYPE_OUT_EXT;
    l_item->header.value = a_value;
    dap_strncpy((char*)l_item->token, a_token, sizeof(l_item->token) - 1);

    int result = dap_chain_datum_tx_add_item(a_tx, l_item);
    DAP_DELETE(l_item);
    return result;
}


dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char* a_token_ticker, uint256_t *a_value, dap_time_t *a_time_unlock, uint256_t a_value_fee, size_t a_tx_num, dap_chain_tx_compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!a_config) {
        return NULL;
    }
    if (!a_addr_from || !a_token_ticker || !a_value) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters");
        return NULL;
    }

    if (dap_chain_addr_check_sum(a_addr_from)) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid source address");
        return NULL;
    }

    for (size_t i = 0; i < a_tx_num; ++i) {
        // if (!a_addr_to || !a_addr_to[i]) {
        //     return NULL;
        // }
        if (a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) {
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid destination address");
            return NULL;
        }
        if (IS_ZERO_256(a_value[i])) {
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "Invalid value");
            return NULL;
        }
    }
#endif
    const char * l_native_ticker = dap_chain_tx_compose_get_native_ticker(a_config->net_name);

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
    if (!dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config)) {
        return NULL;
    }

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_json_t *l_native_outs = NULL;
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
    int l_native_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        if (l_net_fee_used && l_addr_fee)
            DAP_DELETE(l_addr_fee);
        return NULL;
    }
    if (l_single_channel) {
        l_native_outs = l_outs;
        l_native_outputs_count = l_outputs_count;
    } else {
        if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_addr_from, l_native_ticker, &l_native_outs, &l_native_outputs_count, a_config)) {
            dap_json_object_free(l_outs);
            if (l_net_fee_used && l_addr_fee)
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
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        if (l_list_fee_out)
            dap_list_free_full(l_list_fee_out, NULL);
        if (l_net_fee_used && l_addr_fee)
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
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }

    }
    if (a_tx_num > 1) {
        uint32_t l_tx_num = a_tx_num;
        dap_chain_tx_tsd_t *l_out_count = dap_chain_datum_tx_item_tsd_create(&l_tx_num, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        dap_chain_datum_tx_add_item(&l_tx, l_out_count);
    }
    
    if (l_single_channel) { // add 'out' items
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (a_addr_to) {
                if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], l_native_ticker, a_time_unlock ? a_time_unlock[i] : 0) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out' item");
                    return NULL;
                }
            } else {
                if (dap_chain_datum_tx_add_out_without_addr(&l_tx, a_value[i]) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out' without address");
                    return NULL;
                }
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
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
    } else { // add 'out_ext' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (a_addr_to) {
                if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker, a_time_unlock ? a_time_unlock[i] : 0)) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out_ext' item");
                    return NULL;
                }
            } else {
                if (dap_chain_datum_tx_add_out_ext_item_without_addr(&l_tx, a_value[i], a_token_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out_ext' without address");
                    return NULL;
                }
            }
        }
        // coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_total, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add network 'fee' item");
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator's 'fee' item");
                return NULL;
            }
        }
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
    }
    return l_tx;
}

dap_json_t *dap_chain_tx_compose_get_remote_tx_outs(const char *a_token_ticker,  dap_chain_addr_t * a_addr, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_token_ticker || !a_addr || !a_config, NULL);
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s;-mempool_check", 
                                                                      dap_chain_addr_to_str(a_addr), a_token_ticker, a_config->net_name);
    if (!l_json_outs) {
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Failed to get response from RPC request");
        return NULL;
    }

    if (!dap_json_is_array(l_json_outs)) {
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    if (dap_json_array_length(l_json_outs) == 0) {
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is empty");
        return NULL;
    }

    dap_json_t *l_first_array = dap_json_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !dap_json_is_array(l_first_array)) {
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    dap_json_t *l_first_item = dap_json_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        dap_json_object_free(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    dap_json_t *l_outs = NULL;
    dap_json_object_get_ex(l_first_item, "outs", &l_outs);
    if (!l_outs ||
        !dap_json_is_array(l_outs)) {
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


dap_json_t* dap_tx_cond_create_compose(const char *a_net_name, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr,
                                        const char *a_cert_str, const char *a_value_datoshi_str, const char *a_value_fee_str,
                                        const char *a_unit_str, const char *a_value_per_unit_max_str,
                                        const char *a_srv_uid_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, TX_COND_CREATE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }
    
    uint256_t l_value_datoshi = {};    
    uint256_t l_value_fee = {};
    uint256_t l_value_per_unit_max = {};
    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(a_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_SERVICE_UID, "Can't find service UID %s", a_srv_uid_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)a_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT, "Can't recognize unit '%s'. Unit must look like { B | SEC }\n", a_unit_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_datoshi = dap_chain_balance_scan(a_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_datoshi_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_value_fee = dap_chain_balance_scan(a_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_fee_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (a_value_per_unit_max_str)
        l_value_per_unit_max = dap_chain_balance_scan(a_value_per_unit_max_str);

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(a_cert_str);
    if(!l_cert_cond) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND, "Can't find cert '%s'\n", a_cert_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY, "Cert '%s' doesn't contain a valid public key\n", a_cert_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_mempool_compose_tx_create_cond(a_wallet_addr, l_key_cond, a_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }
    DAP_DELETE(l_key_cond);
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(dap_chain_addr_t *a_wallet_addr, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, dap_chain_tx_compose_config_t *a_config)
{
    // check valid param
    if (!a_config->net_name || !*a_config->net_name || !a_key_cond || IS_ZERO_256(a_value) || !a_config->url_str || !*a_config->url_str || a_config->port == 0 || !a_wallet_addr)
        return NULL;

    if (dap_strcmp(dap_chain_tx_compose_get_native_ticker(a_config->net_name), a_token_ticker)) {
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NATIVE_TOKEN_REQUIRED, "Pay for service should be only in native token_ticker\n");
        return NULL;
    }
    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
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
        return NULL;
    }
#endif
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                                         l_value_need,
                                                                         &l_value_transfer, false);
    dap_json_object_free(l_outs);
    if(!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS, "Nothing to transfer (not enough funds)\n");
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
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_key_cond, a_srv_uid, a_value, a_value_per_unit_max, a_unit, a_cond,
                a_cond_size) == 1) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_COND_OUTPUT_FAILED, "Cant add conditional output\n");
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
