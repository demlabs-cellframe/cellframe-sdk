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
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_net_srv_stake_lock.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_tx.h"
#include "dap_net.h"
#include "dap_app_cli.h"
#include "dap_json_rpc.h"
#include "dap_app_cli_net.h"
#include "dap_cli_server.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_node_client.h"

#include "dap_json.h"
#include "dap_rand.h"

#define LOG_TAG "dap_chain_tx_compose"

compose_config_t* dap_compose_config_init(const char *a_net_name, const char *a_url_str,
                                 uint16_t a_port, const char *a_cert_path) {
    if (!a_net_name) {
        return NULL;
    }
    compose_config_t *l_config = DAP_NEW_Z(compose_config_t);
    if (!l_config) {
        return NULL;
    }
    l_config->net_name = a_net_name;
    
    const char *l_url = a_url_str ? a_url_str : dap_compose_get_net_url(a_net_name);
    if (!l_url) {
        DAP_DELETE(l_config);
        return NULL;
    }
    l_config->url_str = l_url;

    uint16_t l_port = a_port ? a_port : dap_compose_get_net_port(a_net_name);
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

dap_json_t* dap_compose_config_return_response_handler(compose_config_t *a_config) {
    if (!a_config || !a_config->response_handler) {
        return NULL;
    }
    dap_json_t* l_response_handler = a_config->response_handler;
    a_config->response_handler = NULL; // Prevent double free
    DAP_DEL_Z(a_config);
    return l_response_handler;
}

static int s_compose_config_deinit(compose_config_t *a_config) {
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

const char* dap_compose_get_net_url(const char* name) {
    // TODO: Get from network configuration, not hardcoded
    UNUSED(name);
    return "http://rpc.cellframe.net";
}

uint16_t dap_compose_get_net_port(const char* name) {
    // TODO: Get from network configuration, not hardcoded
    UNUSED(name);
    return 8081;
}

const char* dap_compose_get_native_ticker(const char* name) {
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

dap_chain_net_id_t dap_get_net_id(const char* name) {
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

int dap_tx_json_tsd_add(dap_json_t *json_tx, dap_json_t *json_add) {
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

static dap_chain_wallet_t* dap_wallet_open_with_pass(const char* a_wallet_name, const char* a_wallets_path, const char* a_pass_str, compose_config_t* a_config) {
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
                                            http_status_code_t http_status_code) {
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

static void s_stage_connected_callback(dap_client_t* a_client, void * a_arg) {
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    UNUSED(a_arg);
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ESTABLISHED;
        pthread_cond_signal(&l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
}

static void s_stage_connected_error_callback(dap_client_t* a_client, void * a_arg) {
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    UNUSED(a_arg);
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ERROR;
        pthread_cond_signal(&l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
}


dap_json_t* dap_enc_request_command_to_rpc(const char *a_request, const char * a_url, uint16_t a_port, const char * a_cert_path) {
    if (!a_request || !a_url || !a_port) {
        return NULL;
    }

    size_t url_len = strlen(a_url);
    dap_chain_node_info_t *node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + url_len + 1);
    if (!node_info) {
        return NULL;
    }
    
    node_info->ext_port = a_port;
    node_info->ext_host_len = dap_strncpy(node_info->ext_host, a_url, url_len + 1) - node_info->ext_host;
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

    int timeout_ms = 50000; //5 sec = 5000 ms
    dap_chain_node_client_t * l_node_client = dap_chain_node_client_create(NULL, node_info, NULL, NULL);
    //handshake
    l_node_client->client = dap_client_new(s_stage_connected_error_callback, l_node_client);
    l_node_client->client->_inheritor = l_node_client;
    dap_client_set_uplink_unsafe(l_node_client->client, &l_node_client->info->address, node_info->ext_host, node_info->ext_port);
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(l_node_client->client);
    dap_client_go_stage(l_node_client->client, STAGE_ENC_INIT, s_stage_connected_callback);
    //wait handshake
    int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
    if (res) {
        dap_chain_node_client_close_unsafe(l_node_client);
        DAP_DEL_Z(node_info);
        return NULL;
    }


    //send request
    dap_json_t * l_response = NULL;
    dap_json_rpc_request_send(l_client_internal, l_request, &l_response, a_cert_path);

    dap_json_rpc_request_free(l_request);
    dap_chain_node_client_close_unsafe(l_node_client);
    DAP_DEL_Z(node_info);
    
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

static dap_json_t* s_request_command_to_rpc(const char *request, compose_config_t *a_config) {
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

static dap_json_t* s_request_command_parse(dap_json_t *l_response, compose_config_t *a_config) {
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

dap_json_t* dap_request_command_to_rpc(const char *request, compose_config_t *a_config) {
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


dap_json_t* dap_request_command_to_rpc_with_params(compose_config_t *a_config, const char *a_method, const char *msg, ...) {
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
    

bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee, compose_config_t *a_config) {
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

bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker,
                                         dap_json_t **l_outs, int *l_outputs_count, compose_config_t *a_config) {
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s", 
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
    TX_CREATE_COMPOSE_INVALID_CONFIG = -9
} tx_create_compose_error_t;

dap_json_t* dap_tx_create_compose(const char *l_net_str, const char *l_token_ticker, const char *l_value_str, const char *l_fee_str, const char *addr_base58_to, 
                                    dap_chain_addr_t *l_addr_from, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {
    if (!l_net_str || !l_token_ticker || !l_value_str || !l_addr_from || !l_url_str) {
        return NULL;
    }
    
    compose_config_t *l_config = dap_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, TX_CREATE_COMPOSE_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t *l_value = NULL;
    uint256_t l_value_fee = {};
    dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;


    l_value_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_value_fee) && (l_fee_str && !dap_strcmp(l_fee_str, "0"))) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "tx_create requires parameter '-fee' to be valid uint256");
        return dap_compose_config_return_response_handler(l_config);
    }

    l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;

    if (addr_base58_to)
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
    else 
        l_addr_el_count = l_value_el_count;

    if (addr_base58_to && l_addr_el_count != l_value_el_count) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "num of '-to_addr' and '-value' should be equal");
        return dap_compose_config_return_response_handler(l_config);
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
        return dap_compose_config_return_response_handler(l_config);
    }
    char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        DAP_DELETE(l_value);
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
        return dap_compose_config_return_response_handler(l_config);
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            DAP_DEL_MULTY(l_value);
            dap_strfreev(l_value_array);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "tx_create requires parameter '-value' to be valid uint256 value");
            return dap_compose_config_return_response_handler(l_config);
        }
    }
    dap_strfreev(l_value_array);

    if (addr_base58_to) {
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            DAP_DELETE(l_value);
            return dap_compose_config_return_response_handler(l_config);
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
            return dap_compose_config_return_response_handler(l_config);
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
                return dap_compose_config_return_response_handler(l_config);
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
            return dap_compose_config_return_response_handler(l_config);
        }
    }

    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create_compose( l_addr_from, l_addr_to, l_token_ticker, l_value, l_value_fee, l_addr_el_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    DAP_DEL_MULTY(l_addr_to, l_value);
    return dap_compose_config_return_response_handler(l_config);
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
        const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num, compose_config_t *a_config)
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
    const char * l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);

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
    if (!dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config)) {
        return NULL;
    }

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_json_t *l_native_outs = NULL;
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
    int l_native_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        if (l_net_fee_used && l_addr_fee)
            DAP_DELETE(l_addr_fee);
        return NULL;
    }
    if (l_single_channel) {
        l_native_outs = l_outs;
        l_native_outputs_count = l_outputs_count;
    } else {
        if (!dap_get_remote_wallet_outs_and_count(a_addr_from, l_native_ticker, &l_native_outs, &l_native_outputs_count, a_config)) {
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
                                                               &l_fee_transfer);
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
                                                            &l_value_transfer);
    
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
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_value[i], l_native_ticker) != 1) {
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
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker) != 1) {
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
    DAP_DELETE(l_addr_fee);
    return l_tx;
}

dap_list_t *dap_ledger_get_list_tx_outs_from_json(dap_json_t * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    return dap_ledger_get_list_tx_outs_from_jso_ex(a_outputs_array, a_outputs_count, a_value_need, a_value_transfer, false);
}

dap_list_t *dap_ledger_get_list_tx_outs_from_json_all(dap_json_t * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    return dap_ledger_get_list_tx_outs_from_jso_ex(a_outputs_array, a_outputs_count, a_value_need, a_value_transfer, true);
}


dap_list_t *dap_ledger_get_list_tx_outs_from_jso_ex(dap_json_t * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer, bool a_need_all_outputs) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    size_t l_out_count = rand() % 10 + 1;
    dap_list_t *l_ret = NULL;
    for (size_t i = 0; i < l_out_count; ++i) {
        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        randombytes(l_item, sizeof(dap_chain_tx_used_out_item_t));
        l_ret = dap_list_append(l_ret, l_item);
    }
    return l_ret;
#endif
    if (!a_outputs_array || a_outputs_count <= 0) {
        return NULL;
    }

    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};

    for (int i = 0; i < a_outputs_count; i++) {
        dap_json_t *l_output = dap_json_array_get_idx(a_outputs_array, i);
        if (!l_output || !dap_json_is_object(l_output)) {
            continue;
        }
        
        dap_json_t *l_value_datosi_obj = NULL;
        dap_json_object_get_ex(l_output, "value_datosi", &l_value_datosi_obj);
        if (!l_value_datosi_obj) {
            continue;
        }
        const char *l_value_str = dap_json_get_string(l_value_datosi_obj);
        uint256_t l_value = dap_chain_balance_scan(l_value_str);

        if (IS_ZERO_256(l_value)) {
            continue;
        }

        dap_json_t *l_prev_hash_obj = NULL;
        dap_json_object_get_ex(l_output, "prev_hash", &l_prev_hash_obj);
        if (!l_prev_hash_obj) {
            continue;
        }
        const char *l_prev_hash_str = dap_json_get_string(l_prev_hash_obj);
        
        dap_json_t *l_out_prev_idx_obj = NULL;
        dap_json_object_get_ex(l_output, "out_prev_idx", &l_out_prev_idx_obj);
        if (!l_out_prev_idx_obj) {
            continue;
        }
        int l_out_idx = dap_json_object_get_int(l_out_prev_idx_obj, NULL);

        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        if (!l_item) {
            continue;
        }

        if (dap_chain_hash_fast_from_str(l_prev_hash_str, &l_item->tx_hash_fast)) {
            DAP_DELETE(l_item);
            continue;
        }

        l_item->num_idx_out = l_out_idx;
        l_item->value = l_value;

        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        if (!l_list_used_out) {
            DAP_DELETE(l_item);
            return NULL;
        }
        
        SUM_256_256(l_value_transfer, l_value, &l_value_transfer);

        if (!a_need_all_outputs && compare256(l_value_transfer, a_value_need) >= 0) {
            break;
        }
    }

    if (compare256(l_value_transfer, a_value_need) >= 0 && l_list_used_out) {
        if (a_value_transfer) {
            *a_value_transfer = l_value_transfer;
        }
        return l_list_used_out;
    } else {
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }
}


dap_json_t *dap_get_remote_tx_outs(const char *a_token_ticker,  dap_chain_addr_t * a_addr, compose_config_t *a_config) {
    if (!a_token_ticker || !a_addr || !a_config) {
        return NULL;
    }
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s", 
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

uint256_t get_balance_from_json(dap_json_t *l_json_outs, const char *a_token_sell) {
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

bool check_token_in_ledger(dap_json_t *l_json_coins, const char *a_token) {
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


typedef enum dap_xchange_compose_error {
    DAP_XCHANGE_COMPOSE_ERROR_NONE = 0,
    DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT,
    DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS,
    DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER,
    DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET,
    DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_CONDITIONAL_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_NETWORK_FEE_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_VALIDATOR_FEE_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_COIN_BACK_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_FEE_BACK_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE
} dap_xchange_compose_error_t;

dap_json_t* dap_tx_create_xchange_compose(const char *l_net_name, const char *l_token_buy, const char *l_token_sell, dap_chain_addr_t *l_wallet_addr, const char *l_value_str, const char *l_rate_str, const char *l_fee_str, const char *l_url_str, uint16_t l_port, const char *l_cert_path){
    compose_config_t *l_config = dap_compose_config_init(l_net_name, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        return dap_compose_config_return_response_handler(l_config);
    }
    uint256_t l_rate = dap_chain_balance_scan(l_rate_str);
    if (IS_ZERO_256(l_rate)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter rate");
        return dap_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter fee");
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_create_compose(l_token_buy,
                                     l_token_sell, l_value, l_rate, l_fee, l_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
        return dap_compose_config_return_response_handler(l_config);
    }

    return dap_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config){
    if (!a_config) {
        return NULL;
    }
    if ( !a_token_buy || !a_token_sell || !a_wallet_addr) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    if (IS_ZERO_256(a_rate)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO, "Invalid parameter rate");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO, "Invalid parameter fee");
        return NULL;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO, "Invalid parameter value sell");
        return NULL;
    }

    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "ledger", "list;coins;-net;%s", a_config->net_name);
    if (!l_json_coins) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }
    if (!check_token_in_ledger(l_json_coins, a_token_sell) || !check_token_in_ledger(l_json_coins, a_token_buy)) {
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER, "Token ticker sell or buy is not found in ledger");
        return NULL;
    }
    dap_json_object_free(l_json_coins);
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                      dap_chain_addr_to_str(a_wallet_addr), a_config->net_name);
    uint256_t l_value = get_balance_from_json(l_json_outs, a_token_sell);
    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(dap_compose_get_native_ticker(a_config->net_name), a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE, "Integer overflow with sum of value and fee");
            return NULL;
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = get_balance_from_json(l_json_outs, dap_compose_get_native_ticker(a_config->net_name));
        if (compare256(l_fee_value, a_fee) == -1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET, "Not enough cash for fee in specified wallet");
            return NULL;
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET, "Not enough cash in specified wallet");
        return NULL;
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED, "Memory allocated");
        return NULL;
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet_addr, dap_compose_get_native_ticker(a_config->net_name), a_config);
    DAP_DEL_Z(l_price);
    return l_tx;
}



dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_seller_addr,
                                                                 const char *a_native_ticker, compose_config_t *a_config)
{
    if (!a_config) {
        return NULL;
    }
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_seller_addr) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    bool l_single_channel = !dap_strcmp(a_price->token_sell, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer; // how many coins to transfer
    uint256_t l_value_need = a_price->datoshi_sell,
              l_net_fee,
              l_total_fee = a_price->fee,
              l_fee_transfer;
    dap_chain_addr_t * l_addr_net_fee = NULL;
    dap_list_t *l_list_fee_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_net_fee, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    dap_json_t *l_outs_native = dap_get_remote_tx_outs(a_native_ticker, a_seller_addr, a_config);
    if (!l_outs_native) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }

    dap_json_t *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = dap_get_remote_tx_outs(a_price->token_sell, a_seller_addr, a_config);
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_count = dap_json_array_length(l_outs);
#else
    dap_json_t *l_outs = NULL;
    dap_json_t *l_outs_native = NULL;
    int l_out_count = 0;
    int l_out_native_count = 0;
#endif

    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            if (dap_strcmp(a_price->token_sell, a_native_ticker))
                dap_json_object_free(l_outs);
            DAP_DELETE(l_addr_net_fee);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_out_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    
    if (dap_strcmp(a_price->token_sell, a_native_ticker))
        dap_json_object_free(l_outs);
    dap_json_object_free(l_outs_native);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        if (l_list_fee_out)
            dap_list_free_full(l_list_fee_out, NULL);
        DAP_DELETE(l_addr_net_fee);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if (!EQUAL_256(l_value_to_items, l_value_transfer) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
        return NULL;
    }
#endif
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
            return NULL;
        }
    }

    // add 'out_cond' & 'out' items

    {
        dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, dap_get_net_id(a_config->net_name), a_price->datoshi_sell,
                                                                                                dap_get_net_id(a_config->net_name), a_price->token_buy, a_price->rate,
                                                                                                a_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_CONDITIONAL_OUTPUT, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output");
                return NULL;
            }
        }
        DAP_DELETE(l_addr_net_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_VALIDATOR_FEE_OUTPUT, "Can't add validator's fee output");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_value_back, a_price->token_sell) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_COIN_BACK_OUTPUT, "Can't add coin back output");
                return NULL;
            }
        }
        // Fee coinback
        if (!l_single_channel) {
            uint256_t l_fee_coinback = {};
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_coinback);
            if (!IS_ZERO_256(l_fee_coinback)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_coinback, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_FEE_BACK_OUTPUT, "Can't add fee back output");
                    return NULL;
                }
            }
        }
    }
    return l_tx;
}


typedef enum dap_tx_cond_create_compose_error {
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_FEE = 1,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_SERVICE_UID,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE,
    TX_COND_CREATE_COMPOSE_ERROR_WALLET_OPEN_FAILED,
    TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY,
    TX_COND_CREATE_COMPOSE_ERROR_NATIVE_TOKEN_REQUIRED,
    TX_COND_CREATE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS,
    TX_COND_CREATE_COMPOSE_ERROR_COND_OUTPUT_FAILED,
    TX_COND_CREATE_COMPOSE_ERROR_COIN_BACK_FAILED
} dap_tx_cond_create_compose_error_t;
dap_json_t* dap_tx_cond_create_compose(const char *a_net_name, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr,
                                        const char *a_cert_str, const char *a_value_datoshi_str, const char *a_value_fee_str,
                                        const char *a_unit_str, const char *a_value_per_unit_max_str,
                                        const char *a_srv_uid_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {    
    compose_config_t *l_config = dap_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
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
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)a_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT, "Can't recognize unit '%s'. Unit must look like { B | SEC }\n", a_unit_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    l_value_datoshi = dap_chain_balance_scan(a_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_datoshi_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    l_value_fee = dap_chain_balance_scan(a_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_fee_str);
        return dap_compose_config_return_response_handler(l_config);
    }
    if (a_value_per_unit_max_str)
        l_value_per_unit_max = dap_chain_balance_scan(a_value_per_unit_max_str);

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(a_cert_str);
    if(!l_cert_cond) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND, "Can't find cert '%s'\n", a_cert_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY, "Cert '%s' doesn't contain a valid public key\n", a_cert_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_mempool_tx_create_cond_compose(a_wallet_addr, l_key_cond, a_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }
    DAP_DELETE(l_key_cond);
    return dap_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(dap_chain_addr_t *a_wallet_addr, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, compose_config_t *a_config)
{
    // check valid param
    if (!a_config->net_name || !*a_config->net_name || !a_key_cond || IS_ZERO_256(a_value) || !a_config->url_str || !*a_config->url_str || a_config->port == 0 || !a_wallet_addr)
        return NULL;

    if (dap_strcmp(dap_compose_get_native_ticker(a_config->net_name), a_token_ticker)) {
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NATIVE_TOKEN_REQUIRED, "Pay for service should be only in native token_ticker\n");
        return NULL;
    }
    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

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
    if (!dap_get_remote_wallet_outs_and_count(a_wallet_addr, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        return NULL;
    }
#endif
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
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

enum cli_hold_compose_error {
    CLI_HOLD_COMPOSE_ERROR_INVALID_CONFIG = -1,
    CLI_HOLD_COMPOSE_ERROR_INVALID_TOKEN = -2,
    CLI_HOLD_COMPOSE_ERROR_INVALID_COINS = -3,
    CLI_HOLD_COMPOSE_ERROR_NO_DELEGATED_TOKEN = -4,
    CLI_HOLD_COMPOSE_ERROR_INVALID_EMISSION_RATE = -5,
    CLI_HOLD_COMPOSE_ERROR_INVALID_COINS_FORMAT = -6,
    CLI_HOLD_COMPOSE_ERROR_INVALID_FEE = -7,
    CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING = -8,
    CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE = -9,
    CLI_HOLD_COMPOSE_ERROR_UNABLE_TO_OPEN_WALLET = -10,
    CLI_HOLD_COMPOSE_ERROR_UNABLE_TO_GET_WALLET_ADDRESS = -11,
    CLI_HOLD_COMPOSE_ERROR_INSUFFICIENT_FUNDS = -12
};

dap_json_t * dap_cli_hold_compose(const char *a_net_name, const char *a_chain_id_str, const char *a_ticker_str, dap_chain_addr_t *a_wallet_addr, const char *a_coins_str, const char *a_time_staking_str,
                                    const char *a_cert_str, const char *a_value_fee_str, const char *a_reinvest_percent_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    
    compose_config_t *l_config = dap_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, CLI_HOLD_COMPOSE_ERROR_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }
    
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_enc_key_t						*l_key_from;
    dap_chain_addr_t					*l_addr_holder;
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value             =   {};

    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "ledger", "list;coins;-net;%s", l_config->net_name);
    if (!l_json_coins) {
        return dap_compose_config_return_response_handler(l_config);
    }
    if (!check_token_in_ledger(l_json_coins, a_ticker_str)) {
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TOKEN, "Invalid token '%s'\n", a_ticker_str);
        return dap_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value = dap_chain_balance_scan(a_coins_str)))) {
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_COINS, "Invalid coins format\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, a_ticker_str);

    if (!check_token_in_ledger(l_json_coins, l_delegated_ticker_str)) {
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_NO_DELEGATED_TOKEN, "No delegated token found\n");
        return dap_compose_config_return_response_handler(l_config);
    }
    dap_json_object_free(l_json_coins);

    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");  // TODO 16126
    // uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);
    // if (IS_ZERO_256(l_emission_rate)) {
    //     printf("Error: Invalid token emission rate\n");
    //     return -8;
    // }

    if (MULT_256_COIN(l_value, l_emission_rate, &l_value_delegated) || IS_ZERO_256(l_value_delegated)) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_EMISSION_RATE, "Invalid coins format\n");
        return dap_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_FEE, "Invalid fee format\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    if (dap_strlen(a_time_staking_str) != 6) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking format\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_month_str[3] = {a_time_staking_str[2], a_time_staking_str[3], 0};
    int l_time_staking_month = atoi(l_time_staking_month_str);
    if (l_time_staking_month < 1 || l_time_staking_month > 12) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking month\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_day_str[3] = {a_time_staking_str[4], a_time_staking_str[5], 0};
    int l_time_staking_day = atoi(l_time_staking_day_str);
    if (l_time_staking_day < 1 || l_time_staking_day > 31) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking day\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    l_time_staking = dap_time_from_str_simplified(a_time_staking_str);
    if (!l_time_staking) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking\n");
        return dap_compose_config_return_response_handler(l_config);
    }
    if (l_time_staking < dap_time_now()) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Time staking is in the past\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    if ( NULL != a_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_balance_coins_scan(a_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_balance_coins_scan("100.0")) == 1) {
            dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
            return dap_compose_config_return_response_handler(l_config);
        }
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(a_reinvest_percent_str);
            if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100) {
                dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
                return dap_compose_config_return_response_handler(l_config);
            }
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
    }
    
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(l_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                       dap_chain_addr_to_str(a_wallet_addr), l_config->net_name);

    uint256_t l_value_balance = get_balance_from_json(l_json_outs, a_ticker_str);
    dap_json_object_free(l_json_outs);
    if (compare256(l_value_balance, l_value) == -1) {
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INSUFFICIENT_FUNDS, "Insufficient funds in wallet\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    // Make transfer transaction
    dap_chain_datum_tx_t *l_tx = dap_stake_lock_datum_create_compose(a_wallet_addr,
                                                           a_ticker_str, l_value, l_value_fee,
                                                           l_time_staking, l_reinvest_percent,
                                                           l_delegated_ticker_str, l_value_delegated, a_chain_id_str, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_compose_config_return_response_handler(l_config);
}

typedef enum {
    STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE = -1,
    STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER = -2,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_CONDITIONAL_OUTPUT = -3,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_NETWORK_FEE_OUTPUT = -4,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_VALIDATOR_FEE_OUTPUT = -5,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_MAIN_TICKER = -6,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_NATIVE_TICKER = -7,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_DELEGATED_TOKEN_EMISSION_OUTPUT = -8,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_SIGN_OUTPUT = -9
} stake_lock_datum_create_error_t;

dap_chain_datum_tx_t * dap_stake_lock_datum_create_compose(dap_chain_addr_t *a_wallet_addr,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_unlock, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                                    const char * a_chain_id_str, compose_config_t *a_config)
{
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // check valid param
    if (!a_config->net_name || !a_wallet_addr || IS_ZERO_256(a_value))
        return NULL;

    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t * l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address( &l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_list_t *l_list_fee_out = NULL;
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
    int l_out_main_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        return NULL;
    }
    if (!dap_strcmp(a_main_ticker, l_native_ticker)) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_get_remote_tx_outs(a_main_ticker, a_wallet_addr, a_config);
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    l_out_main_count = dap_json_array_length(l_outs_main);

    if (l_main_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            return NULL;
        }
    }
#endif
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
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

    // add 'in_ems' item
    {
        dap_chain_id_t l_chain_id = { };
        dap_chain_id_parse(a_chain_id_str, &l_chain_id);
        dap_hash_fast_t l_blank_hash = {};
        dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_blank_hash, a_delegated_ticker_str);
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
    }

    // add 'out_cond' and 'out_ext' items
    {
        uint256_t l_value_pack = {}, l_native_pack = {}; // how much coin add to 'out_ext' items
        dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
                                                        l_uid, a_value, a_time_unlock, a_reinvest_percent);
        if (l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond);
            DAP_DEL_Z(l_tx_out_cond);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_CONDITIONAL_OUTPUT, "Cant add conditional output\n");
            return NULL;
        }

        uint256_t l_value_back = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_NETWORK_FEE_OUTPUT, "Cant add network fee output\n");
                return NULL;
            }
            if (l_main_native)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else
                SUM_256_256(l_native_pack, l_net_fee, &l_native_pack);
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_VALIDATOR_FEE_OUTPUT, "Cant add validator's fee output\n");
                return NULL;
            }
            if (l_main_native)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else
                SUM_256_256(l_native_pack, a_value_fee, &l_native_pack);
        }
        // coin back
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_main_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_MAIN_TICKER, "Cant add coin back output for main ticker\n");
                return NULL;
            }
        }
        // fee coin back
        if (!IS_ZERO_256(l_fee_transfer)) {
            SUBTRACT_256_256(l_fee_transfer, l_native_pack, &l_value_back);
            if (!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_NATIVE_TICKER, "Cant add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add delegated token emission 'out_ext'
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_delegated_value, a_delegated_ticker_str) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_DELEGATED_TOKEN_EMISSION_OUTPUT, "Cant add delegated token emission output\n");
        return NULL;
    }

    return l_tx;
}


typedef enum {
    CLI_TAKE_COMPOSE_OK = 0,
    CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG = -1,
    CLI_TAKE_COMPOSE_ERROR_INVALID_TRANSACTION_HASH = -2,
    CLI_TAKE_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE = -3,
    CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND = -4,
    CLI_TAKE_COMPOSE_ERROR_NO_TX_OUT_CONDITION = -5,
    CLI_TAKE_COMPOSE_ERROR_TX_OUT_ALREADY_USED = -6,
    CLI_TAKE_COMPOSE_ERROR_FAILED_GET_ITEMS_ARRAY = -7,
    CLI_TAKE_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND = -8,
    CLI_TAKE_COMPOSE_ERROR_INVALID_COINS_FORMAT = -9,
    CLI_TAKE_COMPOSE_ERROR_INVALID_FEE_FORMAT = -10,
    CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_OPEN_WALLET = -11,
    CLI_TAKE_COMPOSE_ERROR_OWNER_KEY_NOT_FOUND = -12,
    CLI_TAKE_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED = -13,
    CLI_TAKE_COMPOSE_ERROR_FAILED_TO_CREATE_TX = -14,
    CLI_TAKE_COMPOSE_ERROR_NO_INFO_TX_OUT_USED = -15,
    CLI_TAKE_COMPOSE_ERROR_TX_OUT_NOT_USED = -16,
} cli_take_compose_error_t;

dap_chain_datum_tx_t *s_get_datum_info_from_rpc(
    const char *a_tx_str, compose_config_t *a_config,
    dap_chain_tx_out_cond_subtype_t a_cond_subtype,
    dap_chain_tx_out_cond_t **a_cond_tx, int a_all_outs_unspent, 
    const char **a_token_ticker)
{
    dap_json_t *l_raw_response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s;-tx_to_json", 
                                                                      a_tx_str, a_config->net_name);
    if (!l_raw_response) {
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return NULL;
    }

    dap_json_t *l_response = dap_json_array_get_idx(l_raw_response, 0);
    if (!l_response) {
        dap_json_object_free(l_raw_response);
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND, "No items found in response\n");
        return NULL;
    }
    // No need to call get() in dap_json
    dap_json_object_free(l_raw_response);
    
    dap_chain_datum_tx_t *l_datum = dap_chain_datum_tx_create();
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    dap_json_t * l_json_errors = dap_json_array_new();
    if (dap_chain_tx_datum_from_json(l_response, NULL, l_json_errors, &l_datum, &l_items_count, &l_items_ready) || l_items_count != l_items_ready) {
        dap_json_object_free(l_response);
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_FAILED_TO_CREATE_TX, "Failed to create transaction from json\n");
        dap_chain_datum_tx_delete(l_datum);
        return NULL;
    }
    
    if (a_cond_tx) {
        uint8_t *l_cond_tx = NULL;
        size_t l_item_size = 0;
        int l_item_index = 0;
        TX_ITEM_ITER_TX_TYPE(l_cond_tx, TX_ITEM_TYPE_OUT_COND, l_item_size, l_item_index, l_datum) {
            if (((dap_chain_tx_out_cond_t *)l_cond_tx)->header.subtype == a_cond_subtype) {
                break;
            }
        }
        if (!l_cond_tx) {
            dap_json_object_free(l_response);
            dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND, "No transaction output condition found\n");
            dap_chain_datum_tx_delete(l_datum);
            return NULL;
        }
        *a_cond_tx = (dap_chain_tx_out_cond_t *)l_cond_tx;
    }

    if (a_token_ticker) {
        dap_json_t *l_token_ticker = NULL;
        dap_json_object_get_ex(l_response, "token_ticker", &l_token_ticker);
        if (!l_token_ticker) {
            dap_json_object_free(l_response);
            dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND, "Token ticker not found in response\n");
            return NULL;
        }
        *a_token_ticker = dap_strdup(dap_json_get_string(l_token_ticker));
    }
    dap_json_object_free(l_response);
    return l_datum;
}

dap_json_t* dap_cli_take_compose(const char *a_net_name, const char *a_chain_id_str, dap_chain_addr_t *a_wallet_addr, const char *a_tx_str,
                                    const char *a_value_fee_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path){

    compose_config_t * l_config = dap_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t * l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG, "Unable to init config\n");
        return l_json_obj_ret;
    }

    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    int									l_prev_cond_idx		=	0;
    uint256_t							l_value_delegated	= 	{};
    uint256_t                           l_value_fee     	=	{};
    dap_hash_fast_t						l_tx_hash;
    dap_chain_datum_tx_t                *l_datum = NULL;
    dap_chain_tx_out_cond_t				*l_cond_tx = NULL;
    dap_enc_key_t						*l_owner_key;
    const char *l_ticker_str = NULL;
    if (dap_chain_hash_fast_from_str(a_tx_str, &l_tx_hash)) {
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_TRANSACTION_HASH, "Invalid transaction hash\n");
        return dap_compose_config_return_response_handler(l_config);
    }

    l_datum = s_get_datum_info_from_rpc(a_tx_str, l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_cond_tx, true, &l_ticker_str);
    if (!l_datum) {
        dap_chain_datum_tx_delete(l_datum);
        DAP_DELETE(l_ticker_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);


    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");

    if (IS_ZERO_256(l_emission_rate) ||
        MULT_256_COIN(l_cond_tx->header.value, l_emission_rate, &l_value_delegated) ||
        IS_ZERO_256(l_value_delegated)) {
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_COINS_FORMAT, "Invalid coins format\n");
        dap_chain_datum_tx_delete(l_datum);
        DAP_DELETE(l_ticker_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_FEE_FORMAT, "Invalid fee format\n");
        dap_chain_datum_tx_delete(l_datum);
        DAP_DELETE(l_ticker_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    if (l_cond_tx->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED, "Not enough time has passed for unlocking\n");
        dap_chain_datum_tx_delete(l_datum);
        DAP_DELETE(l_ticker_str);
        return dap_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_t *l_tx = dap_stake_unlock_datum_create_compose(a_wallet_addr, &l_tx_hash, l_prev_cond_idx,
                                          l_ticker_str, l_cond_tx->header.value, l_value_fee,
                                          l_delegated_ticker_str, l_value_delegated, l_config);

    dap_chain_datum_tx_delete(l_datum);
    DAP_DELETE(l_ticker_str);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_compose_config_return_response_handler(l_config);
}


typedef enum {
    TX_STAKE_UNLOCK_COMPOSE_OK = 0,
    TX_STAKE_UNLOCK_COMPOSE_INVALID_PARAMS = -1,
    TX_STAKE_UNLOCK_COMPOSE_NOT_ENOUGH_FUNDS = -2,
    TX_STAKE_UNLOCK_COMPOSE_TOTAL_FEE_MORE_THAN_STAKE = -3,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_NETWORK_FEE_OUTPUT = -4,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_VALIDATOR_FEE_OUTPUT = -5,
    TX_STAKE_UNLOCK_COMPOSE_CANT_SUBTRACT_VALUE_PACK = -6,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_MAIN = -7,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_NATIVE = -8,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_BURNING_OUTPUT = -9,
    TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_DELEGATED = -10
} tx_stake_unlock_compose_error_t;

dap_chain_datum_tx_t *dap_stake_unlock_datum_create_compose(dap_chain_addr_t *a_wallet_addr,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                               compose_config_t *a_config)
{
    // check valid param
    if (!a_config || !a_wallet_addr || dap_hash_fast_is_blank(a_stake_tx_hash)) {
        dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_INVALID_PARAMS, "Invalid parameters\n");
        return NULL;
    }

    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t* l_addr_fee = NULL;

    dap_list_t *l_list_fee_out = NULL, *l_list_used_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    dap_json_t *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        return NULL;
    }

    dap_json_t *l_outs_delegated = dap_get_remote_tx_outs(a_delegated_ticker_str, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        return NULL;
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_delegated_count = dap_json_array_length(l_outs_delegated);
#else
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_delegated = NULL;
    int l_out_native_count = 0;
    int l_out_delegated_count = 0;
#endif

    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    if (!IS_ZERO_256(l_total_fee)) {
        if (!l_main_native) {
            l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_total_fee, 
                                                                &l_fee_transfer);
            if (!l_list_fee_out) {
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
                dap_json_object_free(l_outs_native);
                dap_json_object_free(l_outs_delegated);
                return NULL;
            }
        }
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        else if (compare256(a_value, l_total_fee) == -1) {
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_TOTAL_FEE_MORE_THAN_STAKE, "Total fee more than stake\n");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            return NULL;
        }
#endif
    }
    if (!IS_ZERO_256(a_delegated_value)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_delegated_value, 
                                                               &l_value_transfer);
        if (!l_list_used_out) {
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            return NULL;
        }
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in_cond' & 'in' items
    {
        dap_chain_datum_tx_add_in_cond_item(&l_tx, a_stake_tx_hash, a_prev_cond_idx, 0);
        if (l_list_used_out) {
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
            dap_list_free_full(l_list_used_out, NULL);
        }
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }
    }

    // add 'out_ext' items
    uint256_t l_value_back;
    {
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        // Network fee
        if(l_net_fee_used){
            if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker)){
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output\n");
                return NULL;
            }
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
            {
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            }
            else {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_VALIDATOR_FEE_OUTPUT, "Can't add validator's fee output\n");
                return NULL;
            }
        }
        // coin back
        //SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
        if(l_main_native){
             if (SUBTRACT_256_256(a_value, l_value_pack, &l_value_back)) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_SUBTRACT_VALUE_PACK, "Can't subtract value pack from value\n");
                return NULL;
            }
            if(!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_main_ticker)!=1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_MAIN, "Can't add coin back output for main ticker\n");
                    return NULL;
                }
            }
        } else {
            SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_value, a_main_ticker)!=1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_MAIN, "Can't add coin back output for main ticker\n");
                return NULL;
            }
            else
            {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker)!=1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_NATIVE, "Can't add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add burning 'out_ext'
    if (!IS_ZERO_256(a_delegated_value)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &c_dap_chain_addr_blank,
                                               a_delegated_value, a_delegated_ticker_str) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_BURNING_OUTPUT, "Can't add burning output for delegated value\n");
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, a_delegated_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_delegated_ticker_str) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_DELEGATED, "Can't add coin back output for delegated ticker\n");
                return NULL;
            }
        }
    }

    return l_tx;
}

typedef enum {
    GET_KEY_DELEGATING_MIN_VALUE_OK = 0,
    GET_KEY_DELEGATING_MIN_VALUE_FAILED_TO_GET_RESPONSE = -1,
    GET_KEY_DELEGATING_MIN_VALUE_INVALID_RESPONSE_FORMAT = -2,
    GET_KEY_DELEGATING_MIN_VALUE_SUMMARY_NOT_FOUND = -3,
    GET_KEY_DELEGATING_MIN_VALUE_MIN_VALUE_NOT_FOUND = -4,
    GET_KEY_DELEGATING_MIN_VALUE_INVALID_VALUE_FORMAT = -5,
    GET_KEY_DELEGATING_MIN_VALUE_UNRECOGNIZED_NUMBER = -6
} get_key_delegating_min_value_error_t;

uint256_t s_get_key_delegating_min_value(compose_config_t *a_config){

    uint256_t l_key_delegating_min_value = uint256_0;
    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "list;keys;-net;%s", a_config->net_name);
    if (!response) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return l_key_delegating_min_value;
    }

    dap_json_t *response_array = dap_json_array_get_idx(response, 0);
    if (!response_array) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_RESPONSE_FORMAT, "Invalid response format\n");
        return l_key_delegating_min_value;
    }

    dap_json_t *summary_obj = dap_json_array_get_idx(response_array, dap_json_array_length(response_array) - 1);
    if (!summary_obj) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_SUMMARY_NOT_FOUND, "Summary object not found in response\n");
        return l_key_delegating_min_value;
    }

    dap_json_t *key_delegating_min_value_obj = NULL;
    dap_json_object_get_ex(summary_obj, "key_delegating_min_value", &key_delegating_min_value_obj);
    if (!key_delegating_min_value_obj) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_MIN_VALUE_NOT_FOUND, "Key delegating min value not found in summary\n");
        return l_key_delegating_min_value;
    }

    const char *key_delegating_min_value_str = dap_json_get_string(key_delegating_min_value_obj);
    if (!key_delegating_min_value_str) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_VALUE_FORMAT, "Invalid key_delegating_min_value format\n");
        return l_key_delegating_min_value;
    }

    l_key_delegating_min_value = dap_chain_balance_scan(key_delegating_min_value_str);
    if (IS_ZERO_256(l_key_delegating_min_value)) {
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_UNRECOGNIZED_NUMBER, "Unrecognized number in key_delegating_min_value\n");
        return l_key_delegating_min_value;
    }

    return l_key_delegating_min_value;
}




// ====================================================================
// VOTING compose functions moved to modules/service/voting/
// All voting-related compose functions are now in:
//   - dap_chain_net_srv_voting_compose.c (implementation)
//   - dap_chain_net_srv_voting_compose.h (declarations)
// 
// Functions moved:
//   - dap_cli_voting_compose()
//   - dap_chain_net_vote_create_compose()
//   - dap_cli_vote_compose()
//   - dap_chain_net_vote_voting_compose()
// 
// To use these functions, include:
//   #include "dap_chain_net_srv_voting_compose.h"
// ====================================================================


typedef enum {
    DAP_CLI_STAKE_INVALIDATE_OK = 0,
    DAP_CLI_STAKE_INVALIDATE_CERT_NOT_FOUND = -1,
    DAP_CLI_STAKE_INVALIDATE_PRIVATE_KEY_MISSING = -2,
    DAP_CLI_STAKE_INVALIDATE_WRONG_CERT = -3,
    DAP_CLI_STAKE_INVALIDATE_LEDGER_ERROR = -4,
    DAP_CLI_STAKE_INVALIDATE_INVALID_TX_HASH = -5,
    DAP_CLI_STAKE_INVALIDATE_NOT_DELEGATED = -6,
    DAP_CLI_STAKE_INVALIDATE_NO_DELEGATE_OUT = -7,
    DAP_CLI_STAKE_INVALIDATE_PREV_TX_NOT_FOUND = -8,
    DAP_CLI_STAKE_INVALIDATE_TX_EXISTS = -9,
    DAP_CLI_STAKE_INVALIDATE_WALLET_NOT_FOUND = -10,
    DAP_CLI_STAKE_INVALIDATE_COMPOSE_ERROR = -11,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_LEDGER_ERROR = -12,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND = -13,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT = -14,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_HASH_NOT_FOUND = -15,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_ERROR = -16,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_NOT_FOUND = -17,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_NOT_FOUND = -18,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_DECODE_ERROR = -19,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_WRONG_OWNER = -20,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TOKEN_NOT_FOUND = -21,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND = -22,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS = -23,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR = -24,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR = -25,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR = -26,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR = -27,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR = -28,
    DAP_CLI_STAKE_INVALIDATE_FEE_ERROR = -29
} dap_cli_stake_invalidate_error_t;
dap_json_t* dap_cli_srv_stake_invalidate_compose(const char *a_net_str, const char *a_tx_hash_str, dap_chain_addr_t *a_wallet_addr, 
                                                  const char *a_cert_str, const char *a_fee_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path)
{
    compose_config_t* l_config = dap_compose_config_init(a_net_str, a_url_str, a_port, a_cert_path);
    dap_hash_fast_t l_tx_hash = {};

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_FEE_ERROR, "Unrecognized number in '-fee' param");
        return dap_compose_config_return_response_handler(l_config);
    }

    if (a_tx_hash_str) {
        dap_chain_hash_fast_from_str(a_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        if (a_cert_str) {
            dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_str);
            if (!l_cert) {
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_CERT_NOT_FOUND, "Specified certificate not found");
                return dap_compose_config_return_response_handler(l_config);
            }
            if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_PRIVATE_KEY_MISSING, "Private key missing in certificate");
                return dap_compose_config_return_response_handler(l_config);
            }
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, dap_get_net_id(a_net_str))) {
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_WRONG_CERT, "Wrong certificate");
                return dap_compose_config_return_response_handler(l_config);
            }
        }
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_signing_addr);

        dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;keys;-net;%s", l_config->net_name);
        if (!l_json_coins) {
            return dap_compose_config_return_response_handler(l_config);
        }
        
        int items_count = dap_json_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            dap_json_t *item = dap_json_array_get_idx(l_json_coins, i);
            dap_json_t *l_node_addr_obj = NULL;
            dap_json_object_get_ex(item, "node_addr", &l_node_addr_obj);
            const char *node_addr_str = l_node_addr_obj ? dap_json_get_string(l_node_addr_obj) : NULL;
            if (node_addr_str && !dap_strcmp(l_addr_str, node_addr_str)) {
                dap_json_t *l_tx_hash_obj = NULL;
                dap_json_object_get_ex(item, "tx_hash", &l_tx_hash_obj);
                const char *tx_hash_str = l_tx_hash_obj ? dap_json_get_string(l_tx_hash_obj) : NULL;
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_tx_hash)) {
                    dap_json_object_free(l_json_coins);
                    dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_INVALID_TX_HASH, "Invalid transaction hash format");
                    return dap_compose_config_return_response_handler(l_config);
                }
                found = true;
                break;
            }
        }
        dap_json_object_free(l_json_coins);
        if (!found) {
            dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_NOT_DELEGATED, "Specified certificate/pkey hash is not delegated");
            return dap_compose_config_return_response_handler(l_config);
        }
    }

    const char *l_tx_hash_str_tmp = a_tx_hash_str ? a_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);


    dap_json_t *l_json_response = dap_request_command_to_rpc_with_params(l_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                      l_tx_hash_str_tmp, l_config->net_name);
    if (!l_json_response) {
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_json_t *l_json_items = dap_json_array_get_idx(l_json_response, 0);
    dap_json_t *l_temp_items = NULL;
    dap_json_object_get_ex(l_json_items, "items", &l_temp_items);
    if (l_temp_items) {
        l_json_items = l_temp_items;
    }
    bool has_delegate_out = false;
    if (l_json_items) {
        int items_count = dap_json_array_length(l_json_items);
        for (int i = 0; i < items_count; i++) {
            dap_json_t *item = dap_json_array_get_idx(l_json_items, i);
            dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
            if (item_type && strcmp(item_type, "out_cond") == 0) {
                dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
                if (subtype && strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE") == 0) {
                    has_delegate_out = true;
                    break;
                }
            }
        }
    }

    if (!has_delegate_out) {
        dap_json_object_free(l_json_response);
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_NO_DELEGATE_OUT, "No delegate output found in transaction");
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_json_t *l_json_spents = NULL;
    dap_json_object_get_ex(l_json_response, "spent_OUTs", &l_json_spents);
    if (l_json_spents) {
        int spents_count = dap_json_array_length(l_json_spents);
        for (int i = 0; i < spents_count; i++) {
            dap_json_t *spent_item = dap_json_array_get_idx(l_json_spents, i);
            dap_json_t *l_spent_tx_obj = NULL;
            dap_json_object_get_ex(spent_item, "is_spent_by_tx", &l_spent_tx_obj);
            const char *spent_by_tx = l_spent_tx_obj ? dap_json_get_string(l_spent_tx_obj) : NULL;
            if (spent_by_tx) {
                if (dap_chain_hash_fast_from_str(spent_by_tx, &l_tx_hash)) {
                    dap_json_object_free(l_json_response);
                    dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_INVALID_TX_HASH, "Invalid transaction hash format");
                    return dap_compose_config_return_response_handler(l_config);
                }
                l_tx_hash_str_tmp = dap_hash_fast_to_str_static(&l_tx_hash);
                dap_json_t *l_json_prev_tx = dap_request_command_to_rpc_with_params(l_config, "ledger", "tx;info;-hash;%s;-net;%s", 
                                                                      l_tx_hash_str_tmp, l_config->net_name);
                if (!l_json_prev_tx) {
                    dap_json_object_free(l_json_response);
                    dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_PREV_TX_NOT_FOUND, "Previous transaction not found");
                    return dap_compose_config_return_response_handler(l_config);
                }
                dap_json_object_free(l_json_prev_tx);
                break; 
            }
        }
    }
    dap_json_object_free(l_json_response);

    if (a_tx_hash_str) {
        char data[512];
        dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;tx;-net;%s", l_config->net_name);
        if (!l_json_coins) {
            return dap_compose_config_return_response_handler(l_config);
        }

        bool tx_exists = false;
        int tx_count = dap_json_array_length(l_json_coins);
        for (int i = 0; i < tx_count; i++) {
            dap_json_t *tx_item = dap_json_array_get_idx(l_json_coins, i);
            dap_json_t *l_tx_hash_obj = NULL;
            dap_json_object_get_ex(tx_item, "tx_hash", &l_tx_hash_obj);
            const char *tx_hash = l_tx_hash_obj ? dap_json_get_string(l_tx_hash_obj) : NULL;
            if (tx_hash && strcmp(tx_hash, l_tx_hash_str_tmp) == 0) {
                dap_json_object_free(l_json_coins);
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_TX_EXISTS, "Transaction already exists");
                return dap_compose_config_return_response_handler(l_config);
            }
        }
        dap_json_object_free(l_json_coins);
    }


    dap_chain_datum_tx_t *l_tx = dap_stake_tx_invalidate_compose(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_stake_tx_invalidate_compose(dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if(!a_config || !a_config->net_name || !*a_config->net_name || !a_tx_hash || !a_wallet_addr || !a_config->url_str || !*a_config->url_str || a_config->port == 0)
        return NULL;

    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-need_sign;-hash;%s;-net;%s", 
                                                                  dap_hash_fast_to_str_static(a_tx_hash), a_config->net_name);
    if (!response) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_LEDGER_ERROR, "Failed to get ledger info");
        return NULL;
    }
    dap_json_t *l_items_array = dap_json_array_get_idx(response, 0);
    dap_json_t *l_temp_items_array = NULL;
    dap_json_object_get_ex(l_items_array, "items", &l_temp_items_array);
    if (l_temp_items_array) {
        l_items_array = l_temp_items_array;
    }
    if (!l_items_array) {
        dap_json_object_free(response);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND, "Items not found in ledger response");
        return NULL;
    }

    dap_json_t *l_unspent_outs = NULL;
    dap_json_object_get_ex(response, "all_OUTs_yet_unspent", &l_unspent_outs);
    if (l_unspent_outs) {
        const char *all_unspent = dap_json_get_string(l_unspent_outs);
        if (all_unspent && strcmp(all_unspent, "yes") == 0) {
            dap_json_object_free(response);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT, "All outputs are already spent");
            return NULL;
        }
    }

    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    const char * l_tx_prev_hash = NULL;
    int l_prev_cond_idx = 0;

    size_t items_count = dap_json_array_length(l_items_array);
    for (size_t i = 0; i < items_count; i++) {
        dap_json_t *l_item = dap_json_array_get_idx(l_items_array, i);
        dap_json_t *l_item_type_obj = NULL;
        dap_json_object_get_ex(l_item, "type", &l_item_type_obj);
        const char *item_type = l_item_type_obj ? dap_json_get_string(l_item_type_obj) : NULL;

        if (item_type && strcmp(item_type, "out_cond") == 0) {
            dap_json_t *l_subtype_obj = NULL;
            dap_json_object_get_ex(l_item, "subtype", &l_subtype_obj);
            const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
            if (!l_tx_out_cond && strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE") == 0) {
                l_tx_out_cond = DAP_NEW_Z(dap_chain_tx_out_cond_t);
                l_tx_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
                dap_json_t *l_value_obj = NULL;
                dap_json_object_get_ex(l_item, "value", &l_value_obj);
                if (l_value_obj) {
                    const char *value_str = dap_json_get_string(l_value_obj);
                    if (value_str) {
                        l_tx_out_cond->header.value = dap_uint256_scan_uninteger(value_str);
                    }
                }
            }
        } else if (item_type && strcmp(item_type, "in_cond") == 0) {
            dap_json_t *l_tx_prev_hash_obj = NULL;
            dap_json_object_get_ex(l_item, "tx_prev_hash", &l_tx_prev_hash_obj);
            l_tx_prev_hash = l_tx_prev_hash_obj ? dap_json_get_string(l_tx_prev_hash_obj) : NULL;
            if (!l_tx_prev_hash) {
                dap_json_object_free(response);
                DAP_DELETE(l_tx_out_cond);
                dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_HASH_NOT_FOUND, "Previous transaction hash not found");
                return NULL;
            }
            dap_json_t *l_prev_idx_obj = NULL;
            dap_json_object_get_ex(l_item, "tx_out_prev_idx", &l_prev_idx_obj);
            l_prev_cond_idx = l_prev_idx_obj ? dap_json_object_get_int(l_prev_idx_obj, NULL) : 0;
            dap_json_t *response_cond = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                      l_tx_prev_hash, a_config->net_name);
            if (!response_cond) {
                dap_json_object_free(response);
                DAP_DELETE(l_tx_out_cond);
                dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_ERROR, "Failed to get conditional transaction info");
                return NULL;
            }
            dap_json_object_free(response_cond);
        }
    }

    if (!l_tx_out_cond || !l_tx_prev_hash) {
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_NOT_FOUND, "Conditional transaction not found");
        return NULL;
    }

    dap_json_t *l_sig_item = NULL;
    for (size_t i = 0; i < items_count; i++) {
        dap_json_t *l_item = dap_json_array_get_idx(l_items_array, i);
        dap_json_t *l_item_type_obj2 = NULL;
        dap_json_object_get_ex(l_item, "type", &l_item_type_obj2);
        const char *item_type = l_item_type_obj2 ? dap_json_get_string(l_item_type_obj2) : NULL;
        if (item_type && strcmp(item_type, "SIG") == 0) {
            l_sig_item = l_item;
            break;
        }
    }

    if (!l_sig_item) {
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_NOT_FOUND, "Signature item not found");
        return NULL;
    }

    dap_json_t *l_sign_b64_obj = NULL;
    dap_json_object_get_ex(l_sig_item, "sig_b64", &l_sign_b64_obj);
    const char *l_sign_b64_str = l_sign_b64_obj ? dap_json_get_string(l_sign_b64_obj) : NULL;
    if (!l_sign_b64_str) {
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_DECODE_ERROR, "Failed to decode signature");
        return NULL;
    }

    // Calculate string length for the already declared l_sign_b64_str variable
    int64_t l_sign_b64_strlen = l_sign_b64_str ? strlen(l_sign_b64_str) : 0;
    int64_t l_sign_decoded_size = DAP_ENC_BASE64_DECODE_SIZE(l_sign_b64_strlen);
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t, sizeof(dap_chain_tx_sig_t) + l_sign_decoded_size);
    *l_tx_sig = (dap_chain_tx_sig_t) {
        .header = {
            .type = TX_ITEM_TYPE_SIG, .version = 1,
            .sig_size = dap_enc_base64_decode(l_sign_b64_str, l_sign_b64_strlen, l_tx_sig->sig, DAP_ENC_DATA_TYPE_B64_URLSAFE)
        }
    };

    dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign(l_tx_sig);
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_sign(&l_owner_addr, l_sign, dap_get_net_id(a_config->net_name));
    if (!dap_chain_addr_compare(&l_owner_addr, a_wallet_addr)) {
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_WRONG_OWNER, "Wrong transaction owner");
        return NULL;
    }
    
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);

    dap_json_t *l_json_tiker = dap_json_array_get_idx(response, 0);
    dap_json_t *token_ticker_obj = NULL;
    dap_json_object_get_ex(l_json_tiker, "Token_ticker", &token_ticker_obj);
    if (!token_ticker_obj) {
        dap_json_object_get_ex(l_json_tiker, "token_ticker", &token_ticker_obj);
        if (!token_ticker_obj) {
            dap_json_object_free(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TOKEN_NOT_FOUND, "Token ticker not found");
            return NULL;
        }
    }
    const char *l_delegated_ticker = dap_json_get_string(token_ticker_obj);

    dap_json_t *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, &l_owner_addr, a_config);
    if (!l_outs_native) {
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND, "Transaction outputs not found");
        return NULL;
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
#else
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    const char *l_delegated_ticker = "mBUZ";
    dap_json_t *l_outs_native = NULL;
    dap_json_t *response = NULL;
    int l_out_native_count = 0;
    int l_prev_cond_idx = 0;
    dap_chain_addr_t l_owner_addr;
    randombytes(&l_owner_addr, sizeof(l_owner_addr));
    dap_chain_tx_out_cond_t *l_tx_out_cond = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_tx_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    dap_chain_tx_sig_t *l_tx_sig = NULL;
    l_tx_out_cond->header.value._lo.b = rand() % 500;
    l_tx_out_cond->header.value._hi.b = rand() % 100;
#endif
    uint256_t l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t*l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_fee_out = NULL; 
    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_fee_total, 
                                                                &l_fee_transfer);
    if (!l_list_fee_out) {
        dap_json_object_free(l_outs_native);
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        if (l_net_fee_used && l_net_fee_addr)
            DAP_DELETE(l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fees");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_prev_cond_idx, 0);

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_outs_native);
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        if (l_net_fee_used && l_net_fee_addr)
            DAP_DELETE(l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR, "Error adding input items");
        return NULL;
    }
#endif
    // add 'out_ext' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value, l_delegated_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_outs_native);
        dap_json_object_free(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        if (l_net_fee_used && l_net_fee_addr)
            DAP_DELETE(l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR, "Error adding output items");
        return NULL;
    }
    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            dap_json_object_free(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            if (l_net_fee_addr)
                DAP_DELETE(l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR, "Error adding network fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            dap_json_object_free(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            if (l_net_fee_used && l_net_fee_addr)
                DAP_DELETE(l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR, "Error adding fee");
            return NULL;
        }
    }
    // fee coin back
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            dap_json_object_free(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            if (l_net_fee_used && l_net_fee_addr)
                DAP_DELETE(l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR, "Error adding fee back");
            return NULL;
        }
    }
    dap_json_object_free(l_outs_native);
    dap_json_object_free(response);
    DAP_DELETE(l_tx_out_cond);
    DAP_DELETE(l_tx_sig);
    if (l_net_fee_used && l_net_fee_addr)
        DAP_DELETE(l_net_fee_addr);
    return l_tx;
}

dap_chain_net_srv_order_direction_t dap_chain_net_srv_order_direction_from_str(const char* str) {
    dap_chain_net_srv_order_direction_t direction = SERV_DIR_UNDEFINED;
    if (strcmp(str, "BUY") == 0) {
        direction = SERV_DIR_BUY;
    } else if (strcmp(str, "SELL") == 0) {
        direction = SERV_DIR_SELL;
    }
    return direction;
}

dap_chain_net_srv_order_t* dap_check_remote_srv_order(const char* l_net_str, const char* l_order_hash_str, uint256_t* a_tax,
                                                    uint256_t* a_value_max, dap_chain_addr_t* a_sovereign_addr, uint256_t* a_sovereign_tax, dap_json_t* response){
    dap_chain_net_srv_order_t* l_order = NULL;
    dap_json_t *orders_array = dap_json_array_get_idx(response, 0);
    size_t orders_count = dap_json_array_length(orders_array);
    for (size_t i = 0; i < orders_count; i++) {
        dap_json_t *order_obj = dap_json_array_get_idx(orders_array, i);
        dap_json_t *l_order_obj = NULL;
        dap_json_object_get_ex(order_obj, "order", &l_order_obj);
        const char *order_hash_str = l_order_obj ? dap_json_get_string(l_order_obj) : NULL;

        if (strcmp(order_hash_str, l_order_hash_str) == 0) {
            l_order = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, sizeof(dap_chain_net_srv_order_t));
            dap_json_t *l_version_obj = NULL;
            dap_json_object_get_ex(order_obj, "version", &l_version_obj);
            l_order->version = l_version_obj ? dap_json_object_get_int(l_version_obj, NULL) : 0;
            dap_json_t *l_direction_obj = NULL;
            dap_json_object_get_ex(order_obj, "direction", &l_direction_obj);
            l_order->direction = dap_chain_net_srv_order_direction_from_str(l_direction_obj ? dap_json_get_string(l_direction_obj) : NULL);
            dap_json_t *l_created_obj = NULL;
            dap_json_object_get_ex(order_obj, "created", &l_created_obj);
            l_order->ts_created = dap_time_from_str_rfc822(l_created_obj ? dap_json_get_string(l_created_obj) : NULL);
            dap_json_t *l_srv_uid_obj = NULL;
            dap_json_object_get_ex(order_obj, "srv_uid", &l_srv_uid_obj);
            l_order->srv_uid.uint64 = dap_chain_srv_uid_from_str(l_srv_uid_obj ? dap_json_get_string(l_srv_uid_obj) : NULL).uint64;
            dap_json_t *l_price_datoshi_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_datoshi", &l_price_datoshi_obj);
            l_order->price = dap_uint256_scan_uninteger(l_price_datoshi_obj ? dap_json_get_string(l_price_datoshi_obj) : NULL);

            dap_json_t *l_price_token_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_token", &l_price_token_obj);
            const char *price_token_str = l_price_token_obj ? dap_json_get_string(l_price_token_obj) : NULL;
            if (price_token_str) {
                strncpy(l_order->price_ticker, price_token_str, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                l_order->price_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
            }

            dap_json_t *l_units_obj = NULL;
            dap_json_object_get_ex(order_obj, "units", &l_units_obj);
            l_order->units = l_units_obj ? dap_json_object_get_int(l_units_obj, NULL) : 0;

            dap_json_t *l_price_unit_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_unit", &l_price_unit_obj);
            l_order->price_unit = dap_chain_net_srv_price_unit_uid_from_str(l_price_unit_obj ? dap_json_get_string(l_price_unit_obj) : NULL);
            dap_json_t *l_node_addr_obj = NULL;
            dap_json_object_get_ex(order_obj, "node_addr", &l_node_addr_obj);
            dap_chain_node_addr_from_str(&l_order->node_addr, l_node_addr_obj ? dap_json_get_string(l_node_addr_obj) : NULL);

            dap_json_t *l_tx_cond_hash_obj = NULL;
            dap_json_object_get_ex(order_obj, "tx_cond_hash", &l_tx_cond_hash_obj);
            const char *tx_cond_hash_str = l_tx_cond_hash_obj ? dap_json_get_string(l_tx_cond_hash_obj) : NULL;
            if (tx_cond_hash_str) {
                dap_chain_hash_fast_from_str(tx_cond_hash_str, &l_order->tx_cond_hash);
            }
            l_order->ext_size = dap_json_object_get_int(order_obj, "ext_size");

            if (l_order->ext_size > 0) {
                dap_json_t *external_params = NULL;
                if (dap_json_object_get_ex(order_obj, "external_params", &external_params)) {
                    dap_json_t *tax_obj = NULL, *value_max_obj = NULL;
                    if (dap_json_object_get_ex(external_params, "tax", &tax_obj) &&
                        dap_json_object_get_ex(external_params, "maximum_value", &value_max_obj)) {
                        const char *tax_str = dap_json_get_string(tax_obj);
                        const char *value_max_str = dap_json_get_string(value_max_obj);
                        *a_tax = dap_uint256_scan_decimal(tax_str);
                        *a_value_max = dap_uint256_scan_decimal(value_max_str);
                    }
                }
            }

            dap_json_t *conditional_tx_params = NULL;
            dap_json_object_get_ex(order_obj, "conditional_tx_params", &conditional_tx_params);
            if (conditional_tx_params && dap_json_is_object(conditional_tx_params)) {
                dap_json_t *sovereign_tax_obj = NULL;
                dap_json_object_get_ex(conditional_tx_params, "sovereign_tax", &sovereign_tax_obj);
                const char *sovereign_tax_str = sovereign_tax_obj ? dap_json_get_string(sovereign_tax_obj) : NULL;

                dap_json_t *sovereign_addr_obj = NULL;
                dap_json_object_get_ex(conditional_tx_params, "sovereign_addr", &sovereign_addr_obj);
                const char *sovereign_addr_str = sovereign_addr_obj ? dap_json_get_string(sovereign_addr_obj) : NULL;
                *a_sovereign_tax = dap_uint256_scan_decimal(sovereign_tax_str);
                if (sovereign_addr_str) {
                    a_sovereign_addr = dap_chain_addr_from_str(sovereign_addr_str);
                    if (!a_sovereign_addr) {
                        // Invalid sovereign address format
                        DAP_DELETE(l_order);
                        return NULL;
                    }
                }
            }
            break;
        }
    }
    return l_order;
}
typedef enum {
    DAP_GET_REMOTE_SRV_ORDER_RPC_RESPONSE = -1
} dap_get_remote_srv_order_error_t;

dap_chain_net_srv_order_t* dap_get_remote_srv_order(const char* l_order_hash_str, uint256_t* a_tax,
                                                    uint256_t* a_value_max, dap_chain_addr_t* a_sovereign_addr, uint256_t* a_sovereign_tax,
                                                    compose_config_t *a_config){

    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "order;list;staker;-net;%s", 
                                                                  a_config->net_name);
    if (!response) {
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return NULL;
    }

    dap_chain_net_srv_order_t *l_order = dap_check_remote_srv_order(a_config->net_name, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
    dap_json_object_free(response);

    if (!l_order) {
        response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "order;list;validator;-net;%s", 
                                                          a_config->net_name);
        if (!response) {
            dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_RPC_RESPONSE, "Error: Failed to get response from remote node");
            return NULL;
        }
        l_order = dap_check_remote_srv_order(a_config->net_name, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
        dap_json_object_free(response);
    }
    return l_order;
}

typedef enum {
    DAP_GET_REMOTE_SRV_ORDER_SIGN_RPC_RESPONSE = -1,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_FIRST_ELEMENT = -2,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN = -3
} dap_get_remote_srv_order_sign_error_t;

dap_sign_t* dap_get_remote_srv_order_sign(const char* l_order_hash_str, compose_config_t *a_config){

    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "net_srv", "order;dump;-hash;%s;-need_sign;-net;%s", 
                                                                  l_order_hash_str, a_config->net_name);
    if (!response) {
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return NULL;
    }
    dap_json_t *l_response_array = dap_json_array_get_idx(response, 0);
    if (!l_response_array) {
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_FIRST_ELEMENT, "Error: Can't get the first element from the response array");
        dap_json_object_free(response);
        return NULL;
    }

    dap_json_t *sig_b64_obj = NULL;
    if (!dap_json_object_get_ex(l_response_array, "sig_b64", &sig_b64_obj)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN, "Error: Can't get base64-encoded sign from SIG item");
        dap_json_object_free(response);
        return NULL;
    }
    const char *l_sign_b64_str = dap_json_get_string(sig_b64_obj);
    if (!l_sign_b64_str) {
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN, "Error: Can't get base64-encoded sign from SIG item");
        dap_json_object_free(response);
        return NULL;
    }

    // dap_json_t *sig_size_obj = NULL;
    // if (dap_json_object_get_ex(l_response_array, "sig_b64_size", &sig_size_obj)) {
    //     *a_sign_size = dap_json_object_get_int(sig_size_obj, NULL);
    // }
    int64_t l_sign_b64_strlen = strlen(l_sign_b64_str);
    int64_t l_sign_decoded_size = DAP_ENC_BASE64_DECODE_SIZE(l_sign_b64_strlen);
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t, sizeof(dap_chain_tx_sig_t) + l_sign_decoded_size);
    *l_tx_sig = (dap_chain_tx_sig_t) {
        .header = {
            .type = TX_ITEM_TYPE_SIG, .version = 1,
            .sig_size = dap_enc_base64_decode(l_sign_b64_str, l_sign_b64_strlen, l_tx_sig->sig, DAP_ENC_DATA_TYPE_B64_URLSAFE)
        }
    };
    dap_sign_t *l_sign = NULL;
    uint64_t l_sign_size = dap_sign_get_size((dap_sign_t*)l_tx_sig->sig);
    if ( l_sign_size > 0) {
        l_sign = DAP_NEW_Z_SIZE(dap_sign_t, l_sign_size);
        memcpy(l_sign, l_tx_sig->sig, l_sign_size);
    }

    DAP_DEL_Z(l_tx_sig);
    dap_json_object_free(response);
    return l_sign;
}




typedef enum {
    STAKE_DELEGATE_COMPOSE_OK = 0,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE = -1,
    STAKE_DELEGATE_COMPOSE_ERR_WALLET_NOT_FOUND = -2,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND = -3,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG = -4,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_SIGN_TYPE = -5,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY = -6,
    STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED = -7,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR = -8,
    STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND = -9,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE = -10,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED = -11,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED = -12,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER = -13,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT = -14,
    STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE = -15,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE = -16,
    STAKE_DELEGATE_COMPOSE_ERR_NO_ITEMS = -17,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR = -18,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SIGNER_ADDR = -19,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR = -20,
    STAKE_DELEGATE_COMPOSE_ERR_NO_TOKEN_TICKER = -21,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW = -22,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH = -23,
    STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER = -24,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER = -25,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX = -26,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN = -27,
    DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS = -28,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE = -29,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE = -30,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR = -31,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_COND_OUT_ERROR = -32,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR = -33,
    DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR = -34,
    DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR = -35,
    DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR = -36
} stake_delegate_error_t;
dap_json_t* dap_cli_srv_stake_delegate_compose(const char* a_net_str, dap_chain_addr_t *a_wallet_addr, const char* a_cert_str, 
                                        const char* a_pkey_full_str, const char* a_sign_type_str, const char* a_value_str, const char* a_node_addr_str, 
                                        const char* a_order_hash_str, const char* a_url_str, uint16_t a_port, const char* a_cert_path, const char* a_sovereign_addr_str, const char* a_fee_str) {
    compose_config_t *l_config = dap_compose_config_init(a_net_str, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE, "Can't create compose config");
        return l_json_obj_ret;
    }
    dap_chain_addr_t l_signing_addr, l_sovereign_addr = {};
    uint256_t l_sovereign_tax = uint256_0;
    uint256_t l_value = uint256_0;
    if (a_value_str) {
        l_value = dap_chain_balance_scan(a_value_str);
        if (IS_ZERO_256(l_value)) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-value' param");
            return dap_compose_config_return_response_handler(l_config);
        }
    }
    dap_pkey_t *l_pkey = NULL;
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    if (a_cert_str) {
        dap_cert_t *l_signing_cert = dap_cert_find_by_name(a_cert_str);
        if (!l_signing_cert) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND, "Specified certificate not found");
            return dap_compose_config_return_response_handler(l_config);
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, dap_get_net_id(a_net_str))) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG, "Specified certificate is wrong");
            return dap_compose_config_return_response_handler(l_config);
        }
        l_pkey = dap_pkey_from_enc_key(l_signing_cert->enc_key);
    }  else if (a_pkey_full_str) {
        dap_sign_type_t l_type = dap_sign_type_from_str(a_sign_type_str);
        if (l_type.type == SIG_TYPE_NULL) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_WRONG_SIGN_TYPE, "Wrong sign type");
            return dap_compose_config_return_response_handler(l_config);
        }
        l_pkey = dap_pkey_get_from_str(a_pkey_full_str);
        if (!l_pkey) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey string format, can't get pkey_full");
            return dap_compose_config_return_response_handler(l_config);
        }
        if (l_pkey->header.type.type != dap_pkey_type_from_sign_type(l_type).type) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "pkey and sign types is different");
            return dap_compose_config_return_response_handler(l_config);
        }
        dap_chain_hash_fast_t l_hash_public_key = {0};
        if (!dap_pkey_get_hash(l_pkey, &l_hash_public_key)) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey hash format");
            return dap_compose_config_return_response_handler(l_config);
        }
        dap_chain_addr_fill(&l_signing_addr, l_type, &l_hash_public_key, dap_get_net_id(a_net_str));
    }

    dap_chain_node_addr_t l_node_addr = g_node_addr;
    if (a_node_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_addr, a_node_addr_str)) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR, "Unrecognized node addr %s", a_node_addr_str);
            return dap_compose_config_return_response_handler(l_config);
        }
    }
    if (a_order_hash_str) {
        uint256_t l_tax;
        uint256_t l_value_max;
        int l_prev_tx_count = 0;
        dap_chain_net_srv_order_t* l_order = dap_get_remote_srv_order(a_order_hash_str, &l_tax, &l_value_max, &l_sovereign_addr, &l_sovereign_tax, l_config);
        if (!l_order) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND, "Error: Failed to get order from remote node");
            return dap_compose_config_return_response_handler(l_config);
        }
        l_sovereign_tax = l_tax;

        if (l_order->direction == SERV_DIR_BUY) { // Staker order
            const char *l_token_ticker = NULL;
            if (!a_cert_str) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED, "Command 'delegate' requires parameter -cert with this order type");
                return dap_compose_config_return_response_handler(l_config);
            }
            if (l_order->ext_size != 0) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE, "Specified order has invalid size");
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }

            dap_chain_tx_out_cond_t *l_cond_tx = NULL;
            dap_chain_datum_tx_t *l_datum = s_get_datum_info_from_rpc(dap_chain_hash_fast_to_str_static(&l_order->tx_cond_hash), l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_cond_tx, true, &l_token_ticker);
            if (!l_datum) {
                dap_chain_datum_tx_delete(l_datum);
                return dap_compose_config_return_response_handler(l_config);
            }

            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, dap_compose_get_native_ticker(a_net_str));

            if (dap_strcmp(l_token_ticker, l_delegated_ticker)) {
                dap_chain_datum_tx_delete(l_datum);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                return dap_compose_config_return_response_handler(l_config);
            }
            if (l_cond_tx->tsd_size != dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size(true, 0)) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT, "The order's conditional transaction has invalid format");
                dap_chain_datum_tx_delete(l_datum);
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }
            if (compare256(l_cond_tx->header.value, l_order->price)) {
                dap_chain_datum_tx_delete(l_datum);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE, "The order's conditional transaction has different value");
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }
            if (!dap_chain_addr_is_blank(&l_cond_tx->subtype.srv_stake_pos_delegate.signing_addr) ||
                    l_cond_tx->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
                dap_chain_datum_tx_delete(l_datum);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR, "The order's conditional transaction gas not blank address or key");
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }
            l_value = l_order->price;
            dap_chain_datum_tx_delete(l_datum);
        } else {
            if (!a_value_str) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED, "Command 'delegate' requires parameter -value with this order type");
                return dap_compose_config_return_response_handler(l_config);
            }
            if (a_sovereign_addr_str) {
                dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(a_sovereign_addr_str);
                if (!l_spec_addr) {
                    dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR, "Specified address is invalid");
                    return dap_compose_config_return_response_handler(l_config);
                }
                l_sovereign_addr = *l_spec_addr;
                DAP_DELETE(l_spec_addr);
            } else
                l_sovereign_addr = *a_wallet_addr;

            if (a_order_hash_str && compare256(l_value, l_order->price) == -1) {
                const char *l_coin_min_str, *l_value_min_str =
                    dap_uint256_to_char(l_order->price, &l_coin_min_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
                return dap_compose_config_return_response_handler(l_config);
            }
            if (a_order_hash_str && compare256(l_value, l_value_max) == 1) {
                const char *l_coin_max_str, *l_value_max_str =
                    dap_uint256_to_char(l_value_max, &l_coin_max_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH, "Number in '-value' param %s is higher than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_max_str, l_value_max_str);
                return dap_compose_config_return_response_handler(l_config);
            }
            size_t l_sign_size = 0;
            dap_sign_t *l_sign = dap_get_remote_srv_order_sign(a_order_hash_str, l_config);
            if (!l_sign) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER, "Specified order is unsigned");
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }
            dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, dap_get_net_id(a_net_str));
            l_pkey = dap_pkey_get_from_sign(l_sign);
            DAP_DELETE(l_sign);
            char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, dap_compose_get_native_ticker(a_net_str));
            if (dap_strcmp(l_order->price_ticker, l_delegated_ticker_str)) {
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER, "Specified order is invalid");
                DAP_DELETE(l_order);
                return dap_compose_config_return_response_handler(l_config);
            }
            l_node_addr = l_order->node_addr;
        }
        DAP_DELETE(l_order);
        if (compare256(l_sovereign_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
                compare256(l_sovereign_tax, GET_256_FROM_64(100)) == -1) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            return dap_compose_config_return_response_handler(l_config);
        }
        DIV_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
    }
    if (!l_pkey) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED, "pkey not defined");
        return dap_compose_config_return_response_handler(l_config);
    }

    // TODO: need to make sure that the key and node are required verification 
    // int l_check_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
    // if (l_check_result) {
    //     dap_json_compose_error_add(a_json_obj_ret, l_check_result, "Key and node verification error");
    //     dap_enc_key_delete(l_enc_key);
    //     return l_check_result;
    // }
 

    uint256_t l_allowed_min = s_get_key_delegating_min_value(l_config);
    if (compare256(l_value, l_allowed_min) == -1) {
        const char *l_coin_min_str, *l_value_min_str = dap_uint256_to_char(l_allowed_min, &l_coin_min_str);
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                          a_value_str, l_coin_min_str, l_value_min_str);
        return dap_compose_config_return_response_handler(l_config);
    }

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-fee' param");
        return dap_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_t *l_tx = dap_stake_tx_create_compose(a_wallet_addr, l_value, l_fee, &l_signing_addr, &l_node_addr,
                                                   a_order_hash_str ? &l_sovereign_addr : NULL, l_sovereign_tax, l_prev_tx, l_pkey, l_config);
    
    DAP_DELETE(l_pkey);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } 

    return dap_compose_config_return_response_handler(l_config);

}

dap_chain_datum_tx_t *dap_stake_tx_create_compose(dap_chain_addr_t *a_wallet_addr,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, compose_config_t *a_config)
{
    if  (!a_wallet_addr || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters for transaction creation");
        return NULL;
    }
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; 

    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t * l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);

    dap_list_t *l_list_fee_out = NULL;

#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    dap_json_t *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE, "Not enough funds to pay fee");
        return NULL;
    }

    dap_json_t *l_outs_delegated = dap_get_remote_tx_outs(l_delegated_ticker, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
        return NULL;
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_delegated_count = dap_json_array_length(l_outs_delegated); 
#else
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_delegated = NULL;
    int l_out_native_count = 0;
    int l_out_delegated_count = 0;
#endif

    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                    l_fee_total, 
                                                    &l_fee_transfer);
    if (!l_list_fee_out) {
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_delegated);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE, "Not enough funds to pay fee");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    if (!a_prev_tx) {
        dap_list_t * l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_value, 
                                                               &l_value_transfer);
        if (!l_list_used_out) {
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
            return NULL;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
            goto tx_fail;
        }
#endif
    } else {
        dap_hash_fast_t l_prev_tx_hash;
        dap_hash_fast(a_prev_tx, dap_chain_datum_tx_get_size(a_prev_tx), &l_prev_tx_hash);
        int l_out_num = 0;
        dap_chain_datum_tx_out_cond_get(a_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
        // add 'in' item to buy from conditional transaction
        if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_prev_tx_hash, l_out_num, -1)) {
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
            goto tx_fail;
        }
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
        goto tx_fail;
    }
#endif
    // add 'out_cond' & 'out_ext' items
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr,
                                                                                          a_sovereign_addr, a_sovereign_tax, a_pkey);

    if (!l_tx_out) {
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_COND_OUT_ERROR, "Error creating conditional transaction output");
        goto tx_fail;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);
    if (!a_prev_tx) {
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_delegated_ticker) != 1) {
                dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR, "Error creating transaction output");
                goto tx_fail;
            }
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR, "Error with network fee");
            goto tx_fail;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR, "Error with validator fee");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_fee_back, l_native_ticker) != 1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR, "Error with fee back");
            goto tx_fail;
        }
    }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

static dap_chain_datum_tx_t *dap_order_tx_create_compose(dap_chain_addr_t *a_wallet_addr,
                                               uint256_t a_value, uint256_t a_fee,
                                                uint256_t a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr,
                                                compose_config_t *a_config)
{
    dap_chain_node_addr_t l_node_addr = {};
    return dap_stake_tx_create_compose(a_wallet_addr, a_value, a_fee,
                             (dap_chain_addr_t *)&c_dap_chain_addr_blank, &l_node_addr,
                             a_sovereign_addr, a_sovereign_tax, NULL, NULL, a_config);
}


typedef enum {
    STAKE_ORDER_CREATE_STAKER_OK = 0,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS = -1,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE = -2,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE = -3,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX = -4,
    STAKE_ORDER_CREATE_STAKER_ERR_WALLET_NOT_FOUND = -5,
    STAKE_ORDER_CREATE_STAKER_ERR_KEY_NOT_FOUND = -6,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR = -7,
    STAKE_ORDER_CREATE_STAKER_ERR_TX_CREATE_FAILED = -8,
    STAKE_ORDER_CREATE_STAKER_ERR_JSON_FAILED = -9
} dap_cli_srv_stake_order_create_staker_error_t;
dap_json_t* dap_cli_srv_stake_order_create_staker_compose(const char *l_net_str, const char *l_value_str, const char *l_fee_str, 
                                                          const char *l_tax_str, const char *l_addr_str, dap_chain_addr_t *a_wallet_addr, 
                                                          const char *l_url_str, uint16_t l_port, const char *l_cert_path) {
    compose_config_t *l_config = dap_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE, "Format -value <256 bit integer>");
        return dap_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return dap_compose_config_return_response_handler(l_config);
    }
    uint256_t l_tax = dap_chain_balance_coins_scan(l_tax_str);
    if (compare256(l_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
            compare256(l_tax, GET_256_FROM_64(100)) == -1) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_chain_addr_t l_addr = {};
    if (l_addr_str) {
        dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_addr_str);
        if (!l_spec_addr) {
            dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR, "Specified address is invalid");
            return dap_compose_config_return_response_handler(l_config);
        }
        l_addr = *l_spec_addr;
        DAP_DELETE(l_spec_addr);
    } else
        l_addr = *a_wallet_addr;
    DIV_256(l_tax, GET_256_FROM_64(100), &l_tax);
    dap_chain_datum_tx_t *l_tx = dap_order_tx_create_compose(a_wallet_addr, l_value, l_fee, l_tax, &l_addr, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_compose_config_return_response_handler(l_config);
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
dap_json_t * dap_cli_xchange_order_remove_compose(const char *l_net_str, const char *l_order_hash_str, const char *l_fee_str, dap_chain_addr_t *a_wallet_addr, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {

    compose_config_t *l_config = dap_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return dap_compose_config_return_response_handler(l_config);
    }
    dap_hash_fast_t l_tx_hash = {};
    dap_chain_hash_fast_from_str(l_order_hash_str, &l_tx_hash);
    if (dap_hash_fast_is_blank(&l_tx_hash)) {
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH, "Invalid order hash");
        return dap_compose_config_return_response_handler(l_config);
    }
    char *l_tx_hash_ret = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_order_remove_compose(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }
    
    return dap_compose_config_return_response_handler(l_config);
}

static bool s_process_ledger_response(dap_chain_tx_out_cond_subtype_t a_cond_type, 
                                                dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_out_hash, compose_config_t *a_config) {
    *a_out_hash = *a_tx_hash;
    int l_prev_tx_count = 0;
    dap_chain_hash_fast_t l_hash = {};
    
    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                  dap_chain_hash_fast_to_str_static(a_tx_hash), a_config->net_name);
    if (!response) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return false;
    }
    
    dap_json_t *l_response_array = dap_json_array_get_idx(response, 0);
    if (!l_response_array) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Can't get the first element from the response array");
        dap_json_object_free(response);
        return false;
    }

    dap_json_t *items = NULL;
    if (!dap_json_object_get_ex(l_response_array, "items", &items)) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: No items found in response");
        return false;
    }
    bool l_found = false;
    int items_count = dap_json_array_length(items);
    for (int i = 0; i < items_count; i++) {
        dap_json_t *item = dap_json_array_get_idx(items, i);
        dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
        if (dap_strcmp(item_type, "out_cond") == 0) {
            dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
            if (!dap_strcmp(subtype, dap_chain_tx_out_cond_subtype_to_str(a_cond_type))) {
                dap_json_t *l_hash_obj = NULL;
                dap_json_object_get_ex(item, "hash", &l_hash_obj);
                if (l_hash_obj) {
                    const char *hash_str = dap_json_get_string(l_hash_obj);
                    if (hash_str) {
                        dap_chain_hash_fast_from_str(hash_str, &l_hash);
                    }
                }
                l_prev_tx_count++;
                l_found = true;
                break;
            }
        } else if (dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_cond") == 0 || dap_strcmp(item_type, "out_old") == 0) {
            l_prev_tx_count++;
        }
    }
    if (!l_found) {
        return false;
    }
    bool l_another_tx = false;
    dap_json_t *spent_outs = NULL;
    dap_json_object_get_ex(l_response_array, "spent_OUTs", &spent_outs);
    if (spent_outs) {
        int spent_outs_count = dap_json_array_length(spent_outs);
        for (int i = 0; i < spent_outs_count; i++) {
            dap_json_t *spent_out = dap_json_array_get_idx(spent_outs, i);
            dap_json_t *l_out_obj = NULL;
            dap_json_object_get_ex(spent_out, "OUT - ", &l_out_obj);
            int out_index = l_out_obj ? dap_json_object_get_int(l_out_obj, NULL) : 0;
            if (out_index == l_prev_tx_count) {
                dap_json_t *spent_by_tx_obj = NULL;
                if (dap_json_object_get_ex(spent_out, "is_spent_by_tx", &spent_by_tx_obj)) {
                    const char *spent_by_tx_str = dap_json_get_string(spent_by_tx_obj);
                    if (spent_by_tx_str) {
                        dap_chain_hash_fast_from_str(spent_by_tx_str, &l_hash);
                        l_another_tx = true;
                        break;
                    }
                }
            }
        }
    }
    if (l_another_tx) {
        *a_out_hash = l_hash;
        return true;
    }
    return false;
}

dap_chain_hash_fast_t dap_ledger_get_final_chain_tx_hash_compose(dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only, compose_config_t *a_config)
{
    dap_chain_hash_fast_t l_hash = { };
    if(!a_tx_hash || dap_hash_fast_is_blank(a_tx_hash))
        return l_hash;
    l_hash = *a_tx_hash;

    while(s_process_ledger_response( a_cond_type, a_tx_hash, &l_hash, a_config));

    return l_hash;
}

dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_price_from_order_compose(dap_chain_tx_out_cond_t *a_cond_tx, 
                                                                                    dap_time_t a_ts_created, dap_hash_fast_t *a_order_hash, dap_hash_fast_t *a_hash_out, const char *a_token_ticker,
                                                                                    uint256_t *a_fee, bool a_ret_is_invalid, compose_config_t *a_config)
{
    if (!a_cond_tx || !a_order_hash || !a_config)
        return NULL;
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price)
        return NULL;
    l_price->creation_date = a_ts_created;
    dap_strncpy(l_price->token_buy, a_cond_tx->subtype.srv_xchange.buy_token, sizeof(l_price->token_buy) - 1);

    l_price->order_hash = *a_order_hash;
    dap_strncpy(l_price->token_sell, a_token_ticker, sizeof(l_price->token_sell) - 1);
    l_price->token_sell[sizeof(l_price->token_sell) - 1] = '\0';

    if (a_fee)
        l_price->fee = *a_fee;

    l_price->datoshi_sell = a_cond_tx->header.value;
    l_price->creator_addr = a_cond_tx->subtype.srv_xchange.seller_addr;
    l_price->rate = a_cond_tx->subtype.srv_xchange.rate;
    if ( !dap_hash_fast_is_blank(a_hash_out) ) {
        l_price->tx_hash = *a_hash_out;
        return l_price;
    } else {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "This order have no active conditional transaction");
        if (a_ret_is_invalid) {
            dap_hash_fast_t l_tx_hash_zero = {0};
            l_price->tx_hash = l_tx_hash_zero;
            return l_price;
        }
    }

    return NULL;
}



dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, uint32_t a_prev_cond_idx, compose_config_t *a_config)
{
    if (!a_config) {
        return NULL;
    }

    if (!a_price) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_price NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    if (!a_wallet_addr) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_wallet_addr NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST

    bool l_single_channel = !dap_strcmp(a_tx_ticker, l_native_ticker);

    if (!dap_chain_addr_compare(a_seller_addr, a_wallet_addr)) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER, "Only owner can invalidate exchange transaction");
        return NULL;
    }

#else
    dap_chain_tx_out_cond_t l_cond_tx_obj = { };
    a_cond_tx = &l_cond_tx_obj;
    a_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    a_cond_tx->header.value = a_price->datoshi_sell;
    a_cond_tx->header.srv_uid.uint64 = rand() % 100;
    a_cond_tx->header.ts_expires = 0;
    strcpy(a_cond_tx->subtype.srv_xchange.buy_token, a_price->token_buy);
    a_cond_tx->subtype.srv_xchange.buy_net_id.uint64 = rand() % 100;
    a_cond_tx->subtype.srv_xchange.sell_net_id.uint64 = rand() % 100;
    a_cond_tx->subtype.srv_xchange.rate = a_price->rate;
    a_cond_tx->subtype.srv_xchange.seller_addr = *a_wallet_addr;
    a_cond_tx->tsd_size = 0;
    
    const char *l_tx_ticker = a_price->token_sell;
    bool l_single_channel = true;
    int l_prev_cond_idx = rand() % 100;
#endif
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0);
    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    uint256_t l_total_fee = a_price->fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (!l_single_channel) {
        dap_json_t *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_seller_addr, a_config);
        if (!l_outs_native) {
            return NULL;
        }
        int l_out_native_count = dap_json_array_length(l_outs_native);
        uint256_t l_transfer_fee = {}, l_fee_back = {};
        // list of transaction with 'out' items to get net fee
        dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_transfer_fee);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            return NULL;
        }


        // add 'in' items to net fee
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED, "Can't compose the transaction input");
            return NULL;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, a_cond_tx->header.value, a_tx_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            return NULL;
        }
        // put fee coinback
        SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED, "Cant add fee cachback output");
            return NULL;
        }

            // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                return NULL;
            }
        }


    } else {
        uint256_t l_coin_back = {};
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (compare256(l_total_fee, a_cond_tx->header.value) >= 0) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH, "Total fee is greater or equal than order liquidity");
            return NULL;
        }
#endif
        SUBTRACT_256_256(a_cond_tx->header.value, l_total_fee, &l_coin_back);
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_coin_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            return NULL;
        }

        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                return NULL;
            }
        }

    }

    return l_tx;
}


dap_chain_datum_tx_t* dap_chain_net_srv_order_remove_compose(dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config) {
    if (!a_hash_tx || !a_wallet_addr || !a_config) {
        return NULL;
    }
    if(IS_ZERO_256(a_fee)){
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return NULL;
    }

    dap_time_t ts_created = 0;

    dap_chain_addr_t l_seller_addr = {};
    const char *ts_created_str = NULL;
    const char *token_ticker = NULL;
    uint32_t l_prev_cond_idx = 0;
    dap_hash_fast_t l_hash_out = {};
    dap_chain_tx_out_cond_t* l_cond_tx_last = dap_find_last_xchange_tx(a_hash_tx, &l_seller_addr, a_config, &ts_created_str, &token_ticker, &l_prev_cond_idx, &l_hash_out);

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx_last, ts_created, a_hash_tx, &l_hash_out, token_ticker, &a_fee, false, a_config);
    if (!l_price) {
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_invalidate_compose(l_price, l_cond_tx_last, a_wallet_addr, &l_seller_addr, token_ticker, l_prev_cond_idx, a_config);

    DAP_DELETE(l_price);
    return l_tx;
}
typedef enum dap_tx_create_xchange_purchase_compose_error {
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_NONE = 0,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_WALLET_NOT_FOUND,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE_FAILED,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_NETWORK_ERROR,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_ORDER_NOT_FOUND
} dap_tx_create_xchange_purchase_compose_error_t;
dap_json_t *dap_tx_create_xchange_purchase_compose (const char *a_net_name, const char *a_order_hash, const char* a_value,
                                                     const char* a_fee, dap_chain_addr_t *a_wallet_addr, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    // Input validation
    if (!a_net_name || !a_order_hash || !a_value || !a_fee || !a_wallet_addr || !a_url_str) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid input parameters");
        return l_json_obj_ret;
    }

    compose_config_t *l_config = dap_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_datoshi_buy = dap_chain_balance_scan(a_value);
    if (IS_ZERO_256(l_datoshi_buy)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Value must be greater than 0");
        return dap_compose_config_return_response_handler(l_config);
    }

    uint256_t l_datoshi_fee = dap_chain_balance_scan(a_fee);
    if (IS_ZERO_256(l_datoshi_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return dap_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_hash = {};
    if (dap_chain_hash_fast_from_str(a_order_hash, &l_tx_hash) != 0 || dap_hash_fast_is_blank(&l_tx_hash)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, "Invalid order hash");
        return dap_compose_config_return_response_handler(l_config);
    }

    char *l_str_ret_hash = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_purchase_compose(&l_tx_hash, l_datoshi_buy, l_datoshi_fee,
                                                        a_wallet_addr, &l_str_ret_hash, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        DAP_DELETE(l_str_ret_hash); // Free allocated hash string
        dap_chain_datum_tx_delete(l_tx);
    }

    return dap_compose_config_return_response_handler(l_config);
}


typedef enum dap_chain_net_srv_xchange_purchase_compose_error {
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NONE = 0,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_ITEMS_FOUND,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE
} dap_chain_net_srv_xchange_purchase_compose_error_t;
dap_chain_tx_out_cond_t* dap_find_last_xchange_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  compose_config_t * a_config, 
                                                  const char **a_ts_created_str, const char **a_token_ticker, uint32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out) {
    dap_chain_tx_out_cond_t *l_cond_tx = NULL;
    dap_hash_fast_t l_current_hash = *a_order_hash;
    dap_json_t *response = NULL;
    dap_json_t *l_final_response = NULL;
    dap_json_t *l_response_array = NULL;
    bool l_found_last = false;
    bool l_first_tx = true; // Flag to identify the first transaction

    while (!l_found_last) {
        response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s",
                                                        dap_chain_hash_fast_to_str_static(&l_current_hash), a_config->net_name);
        if (!response) {
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE, 
                                     "Failed to get response from remote node");
            return NULL;
        }

        dap_json_t *l_first_item = dap_json_array_get_idx(response, 0);
        if (!l_first_item) {
            dap_json_object_free(response);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
                                     "Invalid response format");
            return NULL;
        }

        // Get ts_created and token_ticker for the first transaction
        if (!*a_ts_created_str) {
            dap_json_t *ts_created_obj = NULL, *token_ticker_obj = NULL;
            if (dap_json_object_get_ex(l_first_item, "ts_created", &ts_created_obj) &&
                dap_json_object_get_ex(l_first_item, "token_ticker", &token_ticker_obj)) {
                const char *l_temp_ts = dap_json_get_string(ts_created_obj);
                const char *l_temp_ticker = dap_json_get_string(token_ticker_obj);
                if (l_temp_ts && l_temp_ticker) {
                    *a_ts_created_str = l_temp_ts;
                    *a_token_ticker = l_temp_ticker;
            }
        }

        // Extract seller address from the first transaction only
        if (l_first_tx) {
            dap_json_t *l_first_items = NULL;
            if (dap_json_object_get_ex(l_first_item, "items", &l_first_items)) {
                int l_first_items_count = dap_json_array_length(l_first_items);
                for (int i = 0; i < l_first_items_count; i++) {
                    dap_json_t *item = dap_json_array_get_idx(l_first_items, i);
                    dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
                    if (item_type && dap_strcmp(item_type, "SIG") == 0) {
                        dap_json_t *sender_addr_obj = NULL;
                        if (dap_json_object_get_ex(item, "sender_addr", &sender_addr_obj)) {
                            const char *sender_addr_str = dap_json_get_string(sender_addr_obj);
                            if (sender_addr_str) {
                            dap_chain_addr_t *l_temp_addr = dap_chain_addr_from_str(sender_addr_str);
                            if (l_temp_addr) {
                                *a_seller_addr = *l_temp_addr;
                                DAP_DELETE(l_temp_addr);
                                break; // Found seller address, exit the loop
                            } else {
                                // Invalid sender address format
                                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid sender address format in first transaction");
                                dap_json_object_free(response);
                                return NULL;
                            }
                        }
                    }
                }
            }
            l_first_tx = false; // No longer the first transaction
        }

        // First, find the conditional output index in this transaction
        dap_json_t *l_current_items = NULL;
        int l_cond_out_idx = -1;
        if (dap_json_object_get_ex(l_first_item, "items", &l_current_items)) {
            int l_current_items_count = dap_json_array_length(l_current_items);
            int l_out_counter = 0;
            for (int i = 0; i < l_current_items_count; i++) {
                dap_json_t *item = dap_json_array_get_idx(l_current_items, i);
                dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
                if (item_type && (dap_strcmp(item_type, "out_cond") == 0 || dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_ext") == 0 || dap_strcmp(item_type, "old_out") == 0)) {
                    if (dap_strcmp(item_type, "out_cond") == 0) {
                        dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
                        if (subtype && !dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE")) {
                            l_cond_out_idx = l_out_counter;
                            break;
                        }
                    }
                    l_out_counter++;
                }
            }
        }

        dap_json_t *l_spent_outs = NULL;
        if (!dap_json_object_get_ex(l_first_item, "spent_outs", &l_spent_outs) ||
            !l_spent_outs || dap_json_array_length(l_spent_outs) == 0 || l_cond_out_idx == -1) {
            l_found_last = true;
            // Store the final response for processing
            l_final_response = response;
            break;
            
        }

        // Look for the conditional output index in spent_outs
        bool l_found_next = false;
        for (size_t i = 0; i < dap_json_array_length(l_spent_outs); i++) {
            dap_json_t *l_spent_out = dap_json_array_get_idx(l_spent_outs, i);
            dap_json_t *out_obj = NULL, *spent_by_tx_obj = NULL;
            if (dap_json_object_get_ex(l_spent_out, "out", &out_obj) &&
                dap_json_object_get_ex(l_spent_out, "is_spent_by_tx", &spent_by_tx_obj)) {
                int out_value = dap_json_object_get_int(out_obj, NULL);
                if (out_value == l_cond_out_idx) {
                    const char *l_next_hash = dap_json_get_string(spent_by_tx_obj);
                    if (l_next_hash && dap_chain_hash_fast_from_str(l_next_hash, &l_current_hash) == 0) {
                    l_found_next = true;
                    break;
                }
            }
        }

        if (!l_found_next) {
            l_found_last = true;
            // Store the final response for processing
            l_final_response = response;
        } else {
            // Free the current response as we'll get a new one
            dap_json_object_free(response);
        }
    }
    
    if (!l_final_response) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT, "No final response available");
        return NULL;
    }
    
    l_response_array = dap_json_array_get_idx(l_final_response, 0);
    if (!l_response_array) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT, "Can't get the first element from the response array");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *items = NULL;
    if (!dap_json_object_get_ex(l_response_array, "items", &items)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_ITEMS_FOUND, "No items found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    uint32_t l_counter_idx = 0;
    int items_count = dap_json_array_length(items);

    for (int i = 0; i < items_count; i++) {
        dap_json_t *item = dap_json_array_get_idx(items, i);
        dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
        if (!item_type) {
            continue;
        }

        if (dap_strcmp(item_type, "out_cond") == 0) {
            dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
            if (subtype && !dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE")) {
                l_cond_tx = DAP_NEW_Z(dap_chain_tx_out_cond_t);
                if (!l_cond_tx) {
                    dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "Memory allocation failed");
                    dap_json_object_free(l_final_response);
                    return NULL;
                }

                l_cond_tx->header.item_type = TX_ITEM_TYPE_OUT_COND;

                dap_json_t *value_obj = NULL, *uid_obj = NULL, *ts_expires_obj = NULL;
                dap_json_t *buy_token_obj = NULL, *rate_obj = NULL, *tsd_size_obj = NULL;

                if (dap_json_object_get_ex(item, "value", &value_obj)) {
                    const char *value_str = dap_json_get_string(value_obj);
                    l_cond_tx->header.value = dap_chain_balance_scan(value_str);
                }

                l_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;

                if (dap_json_object_get_ex(item, "uid", &uid_obj)) {
                    const char *uid_str = dap_json_get_string(uid_obj);
                    l_cond_tx->header.srv_uid.uint64 = strtoull(uid_str, NULL, 16);
                }

                if (dap_json_object_get_ex(item, "ts_expires", &ts_expires_obj)) {
                    const char *ts_expires_str = dap_json_get_string(ts_expires_obj);
                    l_cond_tx->header.ts_expires = dap_time_from_str_rfc822(ts_expires_str);
                }

                if (dap_json_object_get_ex(item, "buy_token", &buy_token_obj)) {
                    const char *buy_token_str = dap_json_get_string(buy_token_obj);
                    if (buy_token_str) {
                        strncpy(l_cond_tx->subtype.srv_xchange.buy_token, buy_token_str, sizeof(l_cond_tx->subtype.srv_xchange.buy_token) - 1);
                        l_cond_tx->subtype.srv_xchange.buy_token[sizeof(l_cond_tx->subtype.srv_xchange.buy_token) - 1] = '\0';
                    }
                }

                if (dap_json_object_get_ex(item, "rate", &rate_obj)) {
                    const char *rate_str = dap_json_get_string(rate_obj);
                    l_cond_tx->subtype.srv_xchange.rate = dap_chain_balance_scan(rate_str);
                }

                if (dap_json_object_get_ex(item, "tsd_size", &tsd_size_obj)) {
                    l_cond_tx->tsd_size = dap_json_object_get_int(tsd_size_obj, NULL);
                }
                // Set seller address from the first transaction
                l_cond_tx->subtype.srv_xchange.seller_addr = *a_seller_addr;
                *a_prev_cond_idx = l_counter_idx;
            }
            l_counter_idx++;
        } else if (dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_ext") == 0 || dap_strcmp(item_type, "old_out") == 0) {
            l_counter_idx++;
        } else {
            l_counter_idx++;
        }
    }
    } // End of while (!l_found_last) loop

    // Use the final response for extracting final data
    l_response_array = l_final_response;

    if (!l_cond_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "No transaction output condition found");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *final_token_ticker_obj = NULL;
    if (!dap_json_object_get_ex(l_response_array, "token_ticker", &final_token_ticker_obj)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Token_ticker not found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }
    const char *l_final_token_ticker = dap_json_get_string(final_token_ticker_obj);
    if (!l_final_token_ticker) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Token_ticker not found in response");
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }
    *a_token_ticker = dap_strdup(l_final_token_ticker);
    if (!*a_token_ticker) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Failed to allocate token_ticker");
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *final_ts_created_obj = NULL;
    if (!dap_json_object_get_ex(l_response_array, "ts_created", &final_ts_created_obj)) {
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }
    const char *l_final_ts_created = dap_json_get_string(final_ts_created_obj);
    if (!l_final_ts_created) {
        DAP_DELETE(l_cond_tx);
        DAP_DELETE(*a_token_ticker);
        *a_token_ticker = NULL;
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP, "TS_Created not found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }
    *a_ts_created_str = dap_strdup(l_final_ts_created);
    if (!*a_ts_created_str) {
        DAP_DELETE(l_cond_tx);
        DAP_DELETE(*a_token_ticker);
        *a_token_ticker = NULL;
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP, "Failed to allocate ts_created");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_object_free(l_final_response);
    *a_hash_out = l_current_hash;
    return l_cond_tx;
}

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, char **a_hash_out, compose_config_t *a_config){
    if (!a_config || !a_order_hash || !a_wallet_addr || !a_hash_out) {
        return NULL;
    }

    const char *l_ts_created_str = NULL;
    const char *l_token_ticker = NULL;
    uint32_t l_prev_cond_idx = 0;
    dap_chain_addr_t l_seller_addr = {0};
    dap_hash_fast_t l_hash_out = {0};
    dap_chain_tx_out_cond_t *l_cond_tx = dap_find_last_xchange_tx(a_order_hash, &l_seller_addr, a_config, &l_ts_created_str, &l_token_ticker, &l_prev_cond_idx, &l_hash_out);
    if (!l_cond_tx) {
        // Clean up any allocated strings in case of failure
        if (l_ts_created_str) {
            DAP_DELETE(l_ts_created_str);
        }
        if (l_token_ticker) {
            DAP_DELETE(l_token_ticker);
        }
        return NULL;
    }

    dap_time_t l_ts_created = dap_time_from_str_rfc822(l_ts_created_str);

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx, l_ts_created, a_order_hash, &l_hash_out, l_token_ticker, &a_fee, false, a_config);
    if(!l_price){
        DAP_DELETE(l_cond_tx);
        // Clean up allocated strings
        if (l_ts_created_str) {
            DAP_DELETE(l_ts_created_str);
        }
        if (l_token_ticker) {
            DAP_DELETE(l_token_ticker);
        }
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE, "Failed to create price from order");
        return NULL;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_exchange_compose(l_price, a_wallet_addr, a_value, a_fee, l_cond_tx, l_prev_cond_idx, a_config);
    DAP_DELETE(l_cond_tx);
    DAP_DELETE(l_price);
    // Clean up allocated strings
    if (l_ts_created_str) {
        DAP_DELETE(l_ts_created_str);
    }
    if (l_token_ticker) {
        DAP_DELETE(l_token_ticker);
    }
    if (!l_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Failed to create exchange transaction");
        return NULL;
    }
    return l_tx;
}


dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                          uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, uint32_t a_prev_cond_idx, compose_config_t *a_config)
{
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_buyer_addr || !a_cond_tx || !a_config) return NULL;

    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    const char *l_service_ticker = NULL;
    // find the transactions from which to take away coins
    uint256_t l_value_transfer, // how many coins to transfer
              l_value_need = a_datoshi_buy,
              l_net_fee = {},
              l_service_fee,
              l_total_fee = a_datoshi_fee,
              l_fee_transfer;
    dap_chain_addr_t *l_net_fee_addr = NULL, *l_service_fee_addr = NULL;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_price->fee, &l_total_fee);
    uint16_t l_service_fee_type  = 0;

    // Doesn't implement service fee for now
    // bool l_service_fee_used = dap_chain_net_srv_xchange_get_fee(a_price->net->pub.id, &l_service_fee, &l_service_fee_addr, &l_service_fee_type);
    // if (l_service_fee_used) {
    //     switch (l_service_fee_type) {
    //     case SERIVCE_FEE_NATIVE_PERCENT:
    //         MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
    //     case SERVICE_FEE_NATIVE_FIXED:
    //         SUM_256_256(l_total_fee, l_service_fee, &l_total_fee);
    //         l_service_ticker = l_native_ticker;
    //         break;
    //     case SERVICE_FEE_OWN_PERCENT:
    //         MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
    //     case SERVICE_FEE_OWN_FIXED:
    //         SUM_256_256(l_value_need, l_service_fee, &l_value_need);
    //         l_service_ticker = a_price->token_buy;
    //     default:
    //         break;
    //     }
    // }

    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_buyer_addr, a_price->token_buy, &l_outs, &l_outputs_count, a_config)) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        return NULL;
    }
#endif

    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        dap_json_object_free(l_outs);
        return NULL;
    }

    bool l_pay_with_native = !dap_strcmp(a_price->token_sell, l_native_ticker);
    bool l_buy_with_native = !dap_strcmp(a_price->token_buy, l_native_ticker);
    if (!l_pay_with_native) {
        if (l_buy_with_native) {
            SUM_256_256(l_value_need, l_total_fee, &l_value_need);
        } else {
            l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                                l_total_fee, 
                                                                &l_fee_transfer);
            if (!l_list_fee_out) {
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
                dap_json_object_free(l_outs);
                dap_list_free_full(l_list_used_out, NULL);
                return NULL;
            }
        }
    }
    dap_json_object_free(l_outs);

    // Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        dap_list_free_full(l_list_used_out, NULL);
        dap_list_free_full(l_list_fee_out, NULL);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_TX_CREATE_ERROR, "Can't create transaction");
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_list_free_full(l_list_fee_out, NULL);
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Can't compose the transaction input");
        return NULL;
    }
#endif

    if (!l_pay_with_native && !l_buy_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't compose the transaction input");
            return NULL;
        }
#endif
    }

    const dap_chain_addr_t *l_seller_addr = &a_cond_tx->subtype.srv_xchange.seller_addr;
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0)) {
        dap_chain_datum_tx_delete(l_tx);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add conditional input");
        return NULL;
    }

    // add 'out' items
    // transfer selling coins
    uint256_t l_datoshi_sell,
              l_datoshi_buy,
              l_value_back;
    if (!IS_ZERO_256(a_price->rate)) {
        DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);
        if (compare256(a_cond_tx->header.value, l_datoshi_sell) < 0) {
            l_datoshi_sell = a_cond_tx->header.value;
            MULT_256_COIN(l_datoshi_sell, a_price->rate, &l_datoshi_buy);
            uint256_t l_exceed = {}; // Correct requested transfer value
            SUBTRACT_256_256(a_datoshi_buy, l_datoshi_buy, &l_exceed);
            SUBTRACT_256_256(l_value_need, l_exceed, &l_value_need);
        } else
            l_datoshi_buy = a_datoshi_buy;
        
        uint256_t l_value_sell = l_datoshi_sell;
        if (l_pay_with_native) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
            if (compare256(l_datoshi_sell, l_total_fee) <= 0) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Fee is greater or equal than transfer value");
                return NULL;
            }
#endif
            SUBTRACT_256_256(l_datoshi_sell, l_total_fee, &l_value_sell);
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_sell, a_price->token_sell) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add selling coins output");
            return NULL;
        }
    } else {
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_RATE_ERROR, "Can't add selling coins output because price rate is 0");
        return NULL;
    }
    
    if (compare256(a_cond_tx->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(a_cond_tx->header.value, l_datoshi_sell, &l_value_back);
        
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, dap_get_net_id(a_config->net_name), l_value_back,
                    dap_get_net_id(a_config->net_name), a_price->token_buy, a_price->rate,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } 

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins output");
        return NULL;
    }
    
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator fee output");
            return NULL;
        }
    }

    // Add network fee
    if (l_net_fee_used && !IS_ZERO_256(l_net_fee)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add net fee output");
            return NULL;
        }
    }

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins back output");
            return NULL;
        }
    }
    // fee back
    if (!l_pay_with_native && !l_buy_with_native) {
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, l_native_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
    }

    return l_tx;
}


}
}
