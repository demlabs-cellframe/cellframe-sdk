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
#include "dap_chain_common.h"

#include <json-c/json.h>
#define LOG_TAG "dap_chain_tx_compose"

#ifdef DAP_CHAIN_TX_COMPOSE_TEST
#include "../../dap-sdk/crypto/src/rand/dap_rand.h"
#endif

static compose_config_t* s_compose_config_init(const char *a_net_name, const char *a_url_str,
                                 uint16_t a_port, const char *a_cert_path) {
    dap_return_val_if_pass(!a_net_name, NULL);
    compose_config_t *l_config = DAP_NEW_Z_RET_VAL_IF_FAIL(compose_config_t, NULL);
    l_config->net_name = a_net_name;
    
    const char *l_url = a_url_str ? a_url_str : dap_compose_get_net_url(a_net_name);
    if (!l_url) {
        log_it(L_ERROR, "Can't get net url for net name: %s", a_net_name);
        DAP_DELETE(l_config);
        return NULL;
    }
    l_config->url_str = l_url;

    uint16_t l_port = a_port ? a_port : dap_compose_get_net_port(a_net_name);
    if (!l_port) {
        log_it(L_ERROR, "Can't get net port for net name: %s", a_net_name);
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

    log_it_fl(L_DEBUG, "a_net_name: %s, a_url_str: %s, a_port: %d, a_cert_path: %s", a_net_name, l_url, l_port, a_cert_path ? a_cert_path : "NULL");
    l_config->response_handler = json_object_new_object();
    if (!l_config->response_handler) {
        log_it(L_ERROR, "Can't create response handler");
        DAP_DELETE(l_config);
        return NULL;
    }
    return l_config;
}

static json_object* s_compose_config_return_response_handler(compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config || !a_config->response_handler, NULL);
    log_it_fl(L_DEBUG, "a_config: %p", a_config);
    json_object* l_response_handler = a_config->response_handler;
    a_config->response_handler = NULL; // Prevent double free
    DAP_DEL_Z(a_config);
    return l_response_handler;
}

static int s_compose_config_deinit(compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config, -1);
    log_it_fl(L_DEBUG, "a_config: %p", a_config);
    if (a_config->response_handler) {
        json_object_put(a_config->response_handler);
        a_config->response_handler = NULL;
    }
    DAP_DEL_Z(a_config);
    return 0;
}

const char* dap_compose_get_net_url(const char* name) {
    dap_return_val_if_pass(!name, NULL);
    log_it_fl(L_DEBUG, "name: %s", name);
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].url;
        }
    }
    log_it_fl(L_DEBUG, "URL for name %s not found, return NULL", name);
    return NULL;
}

uint16_t dap_compose_get_net_port(const char* name) {
    dap_return_val_if_pass(!name, 0);
    log_it_fl(L_DEBUG, "Name: %s", name);
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].port;
        }
    }
    log_it_fl(L_DEBUG, "Port for name %s not found, return 0", name);
    return 0;
}

static const char* s_get_native_ticker(const char* name) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    return "BUZ";
#endif
    dap_return_val_if_pass(!name, NULL);
    log_it_fl(L_DEBUG, "Name: %s", name);
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].native_ticker;
        }
    }
    log_it_fl(L_DEBUG, "Native ticker for name %s not found, return NULL", name);
    return NULL;
}

dap_chain_net_id_t dap_get_net_id(const char* name) {
    dap_chain_net_id_t empty_id = {.uint64 = 0};
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    randombytes(&empty_id, sizeof(empty_id));
#else
    dap_return_val_if_pass(!name, empty_id);
    log_it_fl(L_DEBUG, "Name: %s", name);
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].net_id;
        }
    }
#endif
    log_it_fl(L_DEBUG, "Net id for name %s not found, return empty id", name);
    return empty_id;
}

int dap_json_compose_error_add(json_object* a_json_obj_reply, int a_code_error, const char *msg, ...)
{
    dap_return_val_if_pass(!a_json_obj_reply || !msg || !json_object_is_type(a_json_obj_reply, json_type_object), -1);
    log_it_fl(L_DEBUG, "a_json_obj_reply: %p, a_code_error: %d, msg: %s", a_json_obj_reply, a_code_error, msg);

    va_list args;
    va_start(args, msg);
    char *l_msg = dap_strdup_vprintf(msg, args); 
    va_end(args);

    if (!l_msg) {
        log_it(L_ERROR, "Can't create message");
        return -1;
    }

    json_object *l_json_arr_errors = NULL;
    if (!json_object_object_get_ex(a_json_obj_reply, "errors", &l_json_arr_errors)) {
        l_json_arr_errors = json_object_new_array();
        if (!l_json_arr_errors) {
            log_it(L_ERROR, "Can't create errors array");
            DAP_DEL_Z(l_msg);
            return -1;
        }
        json_object_object_add(a_json_obj_reply, "errors", l_json_arr_errors);
    }

    json_object* l_obj_error = json_object_new_object();
    if (!l_obj_error) {
        log_it(L_ERROR, "Can't create error object");
        DAP_DEL_Z(l_msg);
        return -1;
    }

    json_object *l_code = json_object_new_int(a_code_error);
    json_object *l_message = json_object_new_string(l_msg);

    if (!l_code || !l_message) {
        log_it(L_ERROR, "Can't create code or message");
        json_object_put(l_code);
        json_object_put(l_message);
        json_object_put(l_obj_error);
        DAP_DEL_Z(l_msg);
        return -1;
    }

    json_object_object_add(l_obj_error, "code", l_code);
    json_object_object_add(l_obj_error, "message", l_message);
    json_object_array_add(l_json_arr_errors, l_obj_error);

    DAP_DEL_Z(l_msg);
    return 0;
}

int dap_tx_json_tsd_add(json_object *json_tx, json_object *json_add) {
    dap_return_val_if_pass(!json_tx || !json_add, -1);
    log_it_fl(L_DEBUG, "json_tx: %p, json_add: %p", json_tx, json_add);

    json_object *items_array;
    if (!json_object_object_get_ex(json_tx, "items", &items_array)) {
        log_it(L_ERROR, "Can't get items array");
        return -1;
    }

    if (!json_object_is_type(items_array, json_type_array)) {
        log_it(L_ERROR, "Items array is not an array");
        return -1;
    }

    json_object_array_add(items_array, json_add);
    return 0;
}

static dap_chain_wallet_t* dap_wallet_open_with_pass(const char* a_wallet_name, const char* a_wallets_path, const char* a_pass_str, compose_config_t* a_config) {
    dap_return_val_if_pass(!a_wallet_name || !a_wallets_path || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_wallet_name: %s, a_wallets_path: %s, a_pass_str: %s, a_config: %p", a_wallet_name, a_wallets_path, a_pass_str, a_config);
    
    dap_chain_wallet_t* l_wallet = dap_chain_wallet_open(a_wallet_name, a_wallets_path, NULL);
    if (!l_wallet) {
        if (access(a_wallets_path, F_OK) == 0) {
            if (!a_pass_str) {
                log_it(L_ERROR, "Password required for wallet %s", a_wallet_name);
                dap_json_compose_error_add(a_config->response_handler, -134, "Password required for wallet %s", a_wallet_name);
                return NULL;
            }
            char l_file_name [MAX_PATH + 1] = "";
            snprintf(l_file_name, sizeof(l_file_name), "%s/%s%s", a_wallets_path, a_wallet_name, ".dwallet");

            l_wallet = dap_chain_wallet_open_file(l_file_name, a_pass_str, NULL);
            if (!l_wallet) {
                log_it(L_ERROR, "Wrong password for wallet %s", a_wallet_name);
                dap_json_compose_error_add(a_config->response_handler, -134, "Wrong password for wallet %s", a_wallet_name);
                return NULL;
            }
        } else {
            log_it(L_ERROR, "Wallet %s not found in the directory %s", a_wallet_name, a_wallets_path);
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
    struct cmd_request *l_cmd_request = DAP_NEW_Z(struct cmd_request);
    if (!l_cmd_request) {
        log_it(L_ERROR, "Can't create cmd request");
        return NULL;
    }
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
    dap_return_if_pass(!a_cmd_request);
    log_it_fl(L_DEBUG, "a_cmd_request: %p", a_cmd_request);

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
    dap_return_if_pass(!l_cmd_request || !a_response);
    log_it_fl(L_DEBUG, "a_response: %p, a_arg: %p", a_response, a_arg);
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
    dap_return_if_pass(!l_cmd_request);
    log_it_fl(L_DEBUG, "a_error_code: %d, a_arg: %p", a_error_code, a_arg);
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
    dap_return_val_if_pass(!a_cmd_request || a_timeout_ms <= 0, -1);
    log_it_fl(L_DEBUG, "a_cmd_request: %p, a_timeout_ms: %d", a_cmd_request, a_timeout_ms);

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
        log_it_fl(L_DEBUG, "response is not NULL");
        pthread_mutex_unlock(&a_cmd_request->wait_mutex);
        return 0;
    }
    
    struct timespec l_cond_timeout;
#ifdef DAP_OS_DARWIN
    l_cond_timeout.tv_sec = a_timeout_ms / 1000;
    l_cond_timeout.tv_nsec = (a_timeout_ms % 1000) * 1000000;
#else
    if (clock_gettime(CLOCK_MONOTONIC, &l_cond_timeout) != 0) {
        log_it(L_ERROR, "Can't get clock");
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

static int s_cmd_request_get_response(struct cmd_request *a_cmd_request, json_object **a_response_out, size_t *a_response_out_size)
{
    dap_return_val_if_pass(!a_cmd_request || !a_response_out || !a_response_out_size, -1);
    log_it_fl(L_DEBUG, "a_cmd_request: %p, a_response_out: %p, a_response_out_size: %p", a_cmd_request, a_response_out, a_response_out_size);

    int ret = 0;
    *a_response_out = NULL;
    *a_response_out_size = 0;

    if (a_cmd_request->error_code) {
        log_it(L_ERROR, "Error code: %d", a_cmd_request->error_code);
        ret = -1;
    } else if (a_cmd_request->response && a_cmd_request->response_size > 0) {
            struct json_tokener *l_tok = json_tokener_new();
            if (l_tok) {
                *a_response_out = json_tokener_parse_ex(l_tok, a_cmd_request->response, a_cmd_request->response_size);
                json_tokener_free(l_tok);
                if (*a_response_out) {
                    *a_response_out_size = a_cmd_request->response_size;
                } else {
                    log_it(L_ERROR, "Can't parse response");
                    ret = -3;
                }
            } else {
                log_it(L_ERROR, "Can't create tokener");
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


json_object* dap_enc_request_command_to_rpc(const char *a_request, const char * a_url, uint16_t a_port, const char * a_cert_path) {
    dap_return_val_if_pass(!a_request || !a_url || !a_port, NULL);
    log_it_fl(L_DEBUG, "a_request: %s, a_url: %s, a_port: %d, a_cert_path: %s", a_request, a_url, a_port, a_cert_path);

    size_t url_len = strlen(a_url);
    dap_chain_node_info_t *node_info = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + url_len + 1, NULL);
    
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
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_creation(l_cmd_arr_str[0], params, l_id_response, 2);
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
        log_it(L_ERROR, "Request failed, error code: %d", res);
        dap_chain_node_client_close_unsafe(l_node_client);
        DAP_DEL_Z(node_info);
        return NULL;
    }


    //send request
    json_object * l_response = NULL;
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

static json_object* s_request_command_to_rpc(const char *request, compose_config_t *a_config) {
    dap_return_val_if_pass(!request || !a_config, NULL);
    log_it_fl(L_DEBUG, "request: %s, a_config: %p", request, a_config);

    json_object *l_response = NULL;
    size_t l_response_size = 0;
    struct cmd_request *l_cmd_request = s_cmd_request_init();

    if (!l_cmd_request) {
        log_it(L_ERROR, "Failed to initialize command request");
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
            log_it(L_ERROR, "Failed to get response");
            dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_FAILED, "Response error code: %d", l_cmd_request->error_code);
            s_cmd_request_free(l_cmd_request);
            return NULL;
        }
    } else {
        log_it(L_ERROR, "Request timed out");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_REQUEST_TIMEOUT, "Request timed out");
        s_cmd_request_free(l_cmd_request);
        return NULL;
    }

    s_cmd_request_free(l_cmd_request);
    return l_response;
}

static json_object* s_request_command_parse(json_object *l_response, compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config || !l_response, NULL);

    json_object *l_result = NULL;
    if (!json_object_object_get_ex(l_response, "result", &l_result)) {
        log_it(L_ERROR, "Failed to get 'result' from response");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESULT_NOT_FOUND, "Failed to get 'result' from response");
        return NULL;
    }

    if (!json_object_is_type(l_result, json_type_array) || json_object_array_length(l_result) == 0) {
        return json_object_get(l_result);
    }

    json_object *first_element = json_object_array_get_idx(l_result, 0);
    if (!first_element) {
        return json_object_get(l_result);
    }

    json_object *errors_array = NULL;
    if (json_object_object_get_ex(first_element, "errors", &errors_array) && 
        json_object_is_type(errors_array, json_type_array)) {
        
        int errors_len = json_object_array_length(errors_array);
        for (int j = 0; j < errors_len; j++) {
            json_object *error_obj = json_object_array_get_idx(errors_array, j);
            if (!error_obj) continue;
            
            json_object *error_code = NULL, *error_message = NULL;
            if (json_object_object_get_ex(error_obj, "code", &error_code) &&
                json_object_object_get_ex(error_obj, "message", &error_message)) {
                dap_json_compose_error_add(a_config->response_handler, 
                                         json_object_get_int(error_code),
                                         json_object_get_string(error_message));
            }
        }
        log_it_fl(L_DEBUG, "errors found in the response");
        return NULL;
    }

    if (l_result) {
        json_object_get(l_result);
    }
    return l_result;
}

json_object* dap_request_command_to_rpc(const char *request, compose_config_t *a_config) {
    dap_return_val_if_pass(!request || !a_config, NULL);
    log_it_fl(L_DEBUG, "request: %s, a_config: %p", request, a_config);


    json_object *l_response = a_config->enc ? 
                            dap_enc_request_command_to_rpc(request, a_config->url_str, a_config->port, a_config->cert_path) 
                            : s_request_command_to_rpc(request, a_config) ;
    if (!l_response) {
        log_it(L_ERROR, "Failed to get response");
        return NULL;
    }

    json_object *l_result = s_request_command_parse(l_response, a_config);
    json_object_put(l_response);
    return l_result;
}


json_object* dap_request_command_to_rpc_with_params(compose_config_t *a_config, const char *a_method, const char *msg, ...) {
    dap_return_val_if_pass(!a_config || !msg || !a_method, NULL);
    log_it_fl(L_DEBUG, "a_config: %p, a_method: %s, msg: %s", a_config, a_method, msg);

    va_list args;
    va_start(args, msg);
    char *l_msg = dap_strdup_vprintf(msg, args);
    va_end(args);

    if (!l_msg) {
        log_it(L_ERROR, "Failed to create message");
        return NULL;
    }

    if (dap_strlen(a_method) * 2 + dap_strlen(l_msg) + 50 >= 512) {
        log_it(L_ERROR, "Message is too long");
        DAP_DELETE(l_msg);
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
                            "{\"method\": \"%s\",\"params\": [\"%s;%s\"],\"id\": \"1\",\"version\": \"2\"}",
                            a_method, a_method, l_msg);
    }

    DAP_FREE(l_msg);

    if (l_ret < 0 || l_ret >= (int)sizeof(data)) {
        log_it(L_ERROR, "Failed to create data");
        return NULL;
    }

    return dap_request_command_to_rpc(data, a_config);
}
    

bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **a_addr_fee, compose_config_t *a_config) {
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    *a_addr_fee = DAP_NEW_Z(dap_chain_addr_t);
    randombytes(*a_addr_fee, sizeof(dap_chain_addr_t));
    a_net_fee->_lo.b = rand() % 500 + 1;
#else
    dap_return_val_if_pass(!a_net_fee || !a_addr_fee || !a_config || !a_config->net_name, false);
    *a_addr_fee = NULL;

    json_object *l_json_get_fee = dap_request_command_to_rpc_with_params(a_config, "net", "get;fee;-net;%s", a_config->net_name);
    if (!l_json_get_fee) {
        log_it(L_ERROR, "Failed to get fee");
        return false;
    }

    json_object *l_first_result = json_object_array_get_idx(l_json_get_fee, 0);
    if (!l_first_result || !json_object_is_type(l_first_result, json_type_object)) {
        log_it(L_ERROR, "Failed to get first result");
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_fees = NULL;
    if (!json_object_object_get_ex(l_first_result, "fees", &l_fees) || 
        !json_object_is_type(l_fees, json_type_object)) {
        log_it(L_ERROR, "Failed to get fees");
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_network = NULL;
    if (!json_object_object_get_ex(l_fees, "network", &l_network) || 
        !json_object_is_type(l_network, json_type_object)) {
        log_it(L_ERROR, "Failed to get network");
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_balance = NULL;
    if (!json_object_object_get_ex(l_network, "balance", &l_balance) || 
        !json_object_is_type(l_balance, json_type_string)) {
        log_it(L_ERROR, "Failed to get balance");
        json_object_put(l_json_get_fee);
        return false;
    }

    const char *l_balance_str = json_object_get_string(l_balance);
    if (!l_balance_str) {
        log_it(L_ERROR, "Failed to get balance string");
        json_object_put(l_json_get_fee);
        return false;
    }

    *a_net_fee = dap_chain_balance_scan(l_balance_str);

    if(IS_ZERO_256(*a_net_fee)) {
        log_it(L_INFO, "%s network fee is zero", a_config->net_name);
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_addr = NULL;
    if (!json_object_object_get_ex(l_network, "addr", &l_addr) || 
        !json_object_is_type(l_addr, json_type_string)) {
        log_it(L_ERROR, "Failed to get addr");
        json_object_put(l_json_get_fee);
        return false;
    }

    const char *l_addr_str = json_object_get_string(l_addr);
    if (!l_addr_str) {
        log_it(L_ERROR, "Failed to get addr string");
        json_object_put(l_json_get_fee);
        return false;
    }

    *a_addr_fee = dap_chain_addr_from_str(l_addr_str);
    json_object_put(l_json_get_fee);

    if (!*a_addr_fee) {
        log_it(L_ERROR, "Failed to get addr");
        return false;
    }
#endif
    return true;
}

bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker,
                                         json_object **l_outs, int *l_outputs_count, compose_config_t *a_config) {
    json_object *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s;-mempool_check", 
                                                                      dap_chain_addr_to_str(a_addr_from), a_token_ticker, a_config->net_name);
    if (!l_json_outs) {
        log_it(L_ERROR, "Failed to get outs");
        return false;
    }

    if (!json_object_is_type(l_json_outs, json_type_array)) {
        log_it(L_ERROR, "Outs is not an array");
        json_object_put(l_json_outs);
        return false;
    }

    if (json_object_array_length(l_json_outs) == 0) {
        log_it(L_ERROR, "Outs is empty");
        json_object_put(l_json_outs);
        return false;
    }

    json_object *l_first_array = json_object_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !json_object_is_type(l_first_array, json_type_array)) {
        log_it(L_ERROR, "First array is not an array");
        json_object_put(l_json_outs);
        return false;
    }

    json_object *l_first_item = json_object_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "First item is NULL");
        json_object_put(l_json_outs);
        return false;
    }

    if (!json_object_object_get_ex(l_first_item, "outs", l_outs) ||
        !json_object_is_type(*l_outs, json_type_array)) {
        log_it(L_ERROR, "Outs is not an array");
        json_object_put(l_json_outs);
        return false;
    }

    *l_outputs_count = json_object_array_length(*l_outs);
    json_object_get(*l_outs);
    json_object_put(l_json_outs);
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

json_object* dap_tx_create_compose(const char *l_net_str, const char *l_token_ticker, const char *l_value_str, const char *l_fee_str, const char *addr_base58_to, 
                                    dap_chain_addr_t *l_addr_from, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {
    dap_return_val_if_pass(!l_net_str || !l_token_ticker || !l_value_str || !l_addr_from || !l_url_str, NULL);
    
    compose_config_t *l_config = s_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
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
        log_it(L_ERROR, "Fee is zero");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "tx_create requires parameter '-fee' to be valid uint256");
        return s_compose_config_return_response_handler(l_config);
    }

    l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;

    if (addr_base58_to)
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
    else 
        l_addr_el_count = l_value_el_count;

    if (addr_base58_to && l_addr_el_count != l_value_el_count) {
        log_it(L_ERROR, "Num of '-to_addr' and '-value' should be equal");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "Num of '-to_addr' and '-value' should be equal");
        return s_compose_config_return_response_handler(l_config);
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        log_it(L_ERROR, "Failed to allocate memory");
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
        return s_compose_config_return_response_handler(l_config);
    }
    char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        log_it(L_ERROR, "Failed to read '-to_addr' arg");
        DAP_DELETE(l_value);
        dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
        return s_compose_config_return_response_handler(l_config);
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            log_it(L_ERROR, "Value is zero");
            DAP_DEL_MULTY(l_value);
            dap_strfreev(l_value_array);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "tx_create requires parameter '-value' to be valid uint256 value");
            return s_compose_config_return_response_handler(l_config);
        }
    }
    dap_strfreev(l_value_array);

    if (addr_base58_to) {
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            log_it(L_ERROR, "%s", c_error_memory_alloc);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_MEMORY_ERROR, "Can't allocate memory");
            DAP_DELETE(l_value);
            return s_compose_config_return_response_handler(l_config);
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            log_it(L_ERROR, "Failed to read '-to_addr' arg");
            DAP_DEL_MULTY(l_addr_to, l_value);
            dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Can't read '-to_addr' arg");
            return s_compose_config_return_response_handler(l_config);
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                log_it(L_ERROR, "Destination address is invalid");
                for (size_t j = 0; j < i; ++j) {
                    DAP_DELETE(l_addr_to[j]);
                }
                DAP_DEL_MULTY(l_addr_to, l_value);
                dap_strfreev(l_addr_base58_to_array);
                dap_json_compose_error_add(l_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Destination address is invalid");
                return s_compose_config_return_response_handler(l_config);
            }
        }
        dap_strfreev(l_addr_base58_to_array);
    }

    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create_compose( l_addr_from, l_addr_to, l_token_ticker, l_value, l_value_fee, l_addr_el_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }

    DAP_DEL_MULTY(l_addr_to, l_value);
    return s_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num, compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    dap_return_val_if_pass(!a_config, NULL);
    if (!a_addr_from || !a_token_ticker || !a_value) {
        log_it(L_ERROR, "Invalid parameters");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters");
        return NULL;
    }

    if (dap_chain_addr_check_sum(a_addr_from)) {
        log_it(L_ERROR, "Invalid source address");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid source address");
        return NULL;
    }

    for (size_t i = 0; i < a_tx_num; ++i) {
        // if (!a_addr_to || !a_addr_to[i]) {
        //     return NULL;
        // }
        if (a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) {
            log_it(L_ERROR, "Invalid destination address");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_ADDR_ERROR, "Invalid destination address");
            return NULL;
        }
        if (IS_ZERO_256(a_value[i])) {
            log_it(L_ERROR, "Invalid value");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_VALUE_ERROR, "Invalid value");
            return NULL;
        }
    }
#endif
    const char * l_native_ticker = s_get_native_ticker(a_config->net_name);

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
        log_it(L_ERROR, "Failed to get net fee and address");
        return NULL;
    }

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    json_object *l_native_outs = NULL;
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    int l_native_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "Failed to get wallet outs and count");
        if (l_net_fee_used && l_addr_fee)
            DAP_DELETE(l_addr_fee);
        return NULL;
    }
    if (l_single_channel) {
        l_native_outs = l_outs;
        l_native_outputs_count = l_outputs_count;
    } else {
        if (!dap_get_remote_wallet_outs_and_count(a_addr_from, l_native_ticker, &l_native_outs, &l_native_outputs_count, a_config)) {
            log_it(L_ERROR, "Failed to get native outs and count");
            json_object_put(l_outs);
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
            log_it(L_ERROR, "Failed to get fee outs");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
            json_object_put(l_outs);
            json_object_put(l_native_outs);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    
    json_object_put(l_outs);
    if (!l_single_channel)
        json_object_put(l_native_outs);
    
    if (!l_list_used_out) {
        log_it(L_ERROR, "Failed to get used outs");
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
        DAP_DEL_Z(l_out_count);
    }
    dap_chain_addr_t l_addr_burn = { };
    if (l_single_channel) { // add 'out' items
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to ? a_addr_to[i] : &l_addr_burn, a_value[i], l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'out' item");
                DAP_DEL_Z(l_addr_fee);
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
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }
        DAP_DEL_Z(l_addr_fee);
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
                log_it(L_ERROR, "Failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
    } else { // add 'out_ext' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to ? a_addr_to[i] : &l_addr_burn, a_value[i], a_token_ticker) != 1) {
                log_it(L_ERROR, "Failed to add 'out_ext' item");
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
                log_it(L_ERROR, "Failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "Failed to add network 'fee' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add network 'fee' item");
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                log_it(L_ERROR, "Failed to add validator's 'fee' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator's 'fee' item");
                return NULL;
            }
        }
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                log_it(L_ERROR, "Failed to add 'coin back' item");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add 'coin back' item");
                return NULL;
            }
        }


    }
    DAP_DELETE(l_addr_fee);
    return l_tx;
}

dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    return dap_ledger_get_list_tx_outs_from_jso_ex(a_outputs_array, a_outputs_count, a_value_need, a_value_transfer, false);
}

dap_list_t *dap_ledger_get_list_tx_outs_from_json_all(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    return dap_ledger_get_list_tx_outs_from_jso_ex(a_outputs_array, a_outputs_count, a_value_need, a_value_transfer, true);
}


dap_list_t *dap_ledger_get_list_tx_outs_from_jso_ex(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer, bool a_need_all_outputs) {
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
    dap_return_val_if_pass(!a_outputs_array || a_outputs_count <= 0, NULL);

    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};

    for (int i = 0; i < a_outputs_count; i++) {
        json_object *l_output = json_object_array_get_idx(a_outputs_array, i);
        if (!l_output || !json_object_is_type(l_output, json_type_object)) {
            continue;
        }
        
        json_object *l_value_datosi_obj = NULL;
        json_object_object_get_ex(l_output, "value_datoshi", &l_value_datosi_obj);
        if (!l_value_datosi_obj) {
            continue;
        }
        const char *l_value_str = json_object_get_string(l_value_datosi_obj);
        uint256_t l_value = dap_chain_balance_scan(l_value_str);

        if (IS_ZERO_256(l_value)) {
            continue;
        }

        json_object *l_prev_hash_obj = NULL;
        json_object_object_get_ex(l_output, "prev_hash", &l_prev_hash_obj);
        if (!l_prev_hash_obj) {
            continue;
        }
        const char *l_prev_hash_str = json_object_get_string(l_prev_hash_obj);
        
        json_object *l_out_prev_idx_obj = NULL;
        json_object_object_get_ex(l_output, "out_prev_idx", &l_out_prev_idx_obj);
        if (!l_out_prev_idx_obj) {
            continue;
        }
        int l_out_idx = json_object_get_int(l_out_prev_idx_obj);

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
            log_it(L_ERROR, "Failed to append item to list");
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
        log_it(L_ERROR, "Failed to get list of used outs");
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }
}


json_object *dap_get_remote_tx_outs(const char *a_token_ticker,  dap_chain_addr_t * a_addr, compose_config_t *a_config) {
    dap_return_val_if_pass(!a_token_ticker || !a_addr || !a_config, NULL);
    log_it_fl(L_DEBUG, "a_token_ticker: %s, a_addr: %s, a_config: %p",
    a_token_ticker, dap_chain_addr_to_str(a_addr), a_config);

    json_object *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-token;%s;-net;%s;-mempool_check", 
                                                                      dap_chain_addr_to_str(a_addr), a_token_ticker, a_config->net_name);
    if (!l_json_outs) {
        log_it(L_ERROR, "Failed to get response from RPC request");
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Failed to get response from RPC request");
        return NULL;
    }

    if (!json_object_is_type(l_json_outs, json_type_array)) {
        log_it(L_ERROR, "Response is not an array");
        json_object_put(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    if (json_object_array_length(l_json_outs) == 0) {
        log_it(L_ERROR, "Response is empty");
        json_object_put(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is empty");
        return NULL;
    }

    json_object *l_first_array = json_object_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !json_object_is_type(l_first_array, json_type_array)) {
        log_it(L_ERROR, "Response is not an array");
        json_object_put(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    json_object *l_first_item = json_object_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "Response is not an array");
        json_object_put(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }

    json_object *l_outs = NULL;
    if (!json_object_object_get_ex(l_first_item, "outs", &l_outs) ||
        !json_object_is_type(l_outs, json_type_array)) {
        log_it(L_ERROR, "Response is not an array");
        json_object_put(l_json_outs);
        dap_json_compose_error_add(a_config->response_handler, DAP_COMPOSE_ERROR_RESPONSE_NULL, "Response is not an array");
        return NULL;
    }
    json_object_get(l_outs);
    json_object_put(l_json_outs);
    return l_outs;
}

uint256_t get_balance_from_json(json_object *l_json_outs, const char *a_token_sell) {
    uint256_t l_value = {};
    if (l_json_outs && json_object_is_type(l_json_outs, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(l_json_outs); i++) {
            json_object *outer_array = json_object_array_get_idx(l_json_outs, i);
            if (json_object_is_type(outer_array, json_type_array)) {
                for (size_t j = 0; j < json_object_array_length(outer_array); j++) {
                    json_object *addr_obj = json_object_array_get_idx(outer_array, j);
                    if (json_object_is_type(addr_obj, json_type_object)) {
                        json_object *tokens = NULL;
                        if (json_object_object_get_ex(addr_obj, "tokens", &tokens) && json_object_is_type(tokens, json_type_array)) {
                            for (size_t k = 0; k < json_object_array_length(tokens); k++) {
                                json_object *token_obj = json_object_array_get_idx(tokens, k);
                                json_object *token = NULL;
                                if (json_object_object_get_ex(token_obj, "token", &token) && json_object_is_type(token, json_type_object)) {
                                    json_object *ticker = NULL;
                                    if (json_object_object_get_ex(token, "ticker", &ticker) && json_object_is_type(ticker, json_type_string)) {
                                        const char *ticker_str = json_object_get_string(ticker);
                                        if (strcmp(ticker_str, a_token_sell) == 0) {
                                            json_object *datoshi = NULL;
                                            if (json_object_object_get_ex(token_obj, "datoshi", &datoshi) && json_object_is_type(datoshi, json_type_string)) {
                                                const char *datoshi_str = json_object_get_string(datoshi);
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

bool check_token_in_ledger(json_object *l_json_coins, const char *a_token) {
    if (json_object_is_type(l_json_coins, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(l_json_coins); i++) {
            json_object *token_array = json_object_array_get_idx(l_json_coins, i);
            if (json_object_is_type(token_array, json_type_array)) {
                for (size_t j = 0; j < json_object_array_length(token_array); j++) {
                    json_object *token_obj = json_object_array_get_idx(token_array, j);
                    json_object *token_name = NULL;
                    if (json_object_object_get_ex(token_obj, "token_name", &token_name) && json_object_is_type(token_name, json_type_string)) {
                        const char *token_name_str = json_object_get_string(token_name);
                        if (strcmp(token_name_str, a_token) == 0) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    log_it(L_ERROR, "Check_token_in_ledger: token %s not found in ledger", a_token);
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

json_object* dap_tx_create_xchange_compose(const char *l_net_name, const char *l_token_buy, const char *l_token_sell, dap_chain_addr_t *l_wallet_addr, const char *l_value_str, const char *l_rate_str, const char *l_fee_str, const char *l_url_str, uint16_t l_port, const char *l_cert_path){
    compose_config_t *l_config = s_compose_config_init(l_net_name, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_rate = dap_chain_balance_scan(l_rate_str);
    if (IS_ZERO_256(l_rate)) {
        log_it(L_ERROR, "Invalid parameter rate, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter rate");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "Invalid parameter fee, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter fee");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_create_compose(l_token_buy,
                                     l_token_sell, l_value, l_rate, l_fee, l_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
        return s_compose_config_return_response_handler(l_config);
    }

    return s_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config){
    dap_return_val_if_pass(!a_config, NULL);
    if ( !a_token_buy || !a_token_sell || !a_wallet_addr) {
        log_it(L_ERROR, "Invalid parameter");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    if (IS_ZERO_256(a_rate)) {
        log_it(L_ERROR, "Invalid parameter rate");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO, "Invalid parameter rate");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter fee");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO, "Invalid parameter fee");
        return NULL;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        log_it(L_ERROR, "Invalid parameter value sell");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO, "Invalid parameter value sell");
        return NULL;
    }

    json_object *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "ledger", "list;coins;-net;%s", a_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "Can't get tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }
    if (!check_token_in_ledger(l_json_coins, a_token_sell) || !check_token_in_ledger(l_json_coins, a_token_buy)) {
        log_it(L_ERROR, "Token ticker sell or buy is not found in ledger");
        json_object_put(l_json_coins);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER, "Token ticker sell or buy is not found in ledger");
        return NULL;
    }
    json_object_put(l_json_coins);
    json_object *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                      dap_chain_addr_to_str(a_wallet_addr), a_config->net_name);
    uint256_t l_value = get_balance_from_json(l_json_outs, a_token_sell);
    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(s_get_native_ticker(a_config->net_name), a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            log_it(L_ERROR, "Integer overflow with sum of value and fee");
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE, "Integer overflow with sum of value and fee");
            return NULL;
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = get_balance_from_json(l_json_outs, s_get_native_ticker(a_config->net_name));
        if (compare256(l_fee_value, a_fee) == -1) {
            log_it(L_ERROR, "Not enough cash for fee in specified wallet");
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET, "Not enough cash for fee in specified wallet");
            return NULL;
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        log_it(L_ERROR, "Not enough cash in specified wallet");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET, "Not enough cash in specified wallet");
        return NULL;
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        log_it(L_ERROR, "%s", c_error_memory_alloc);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED, "Memory allocated");
        return NULL;
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet_addr, s_get_native_ticker(a_config->net_name), a_config);
    DAP_DEL_Z(l_price);
    return l_tx;
}



dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_seller_addr,
                                                                 const char *a_native_ticker, compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config, NULL);
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_seller_addr) {
        log_it(L_ERROR, "Invalid parameter");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
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
    json_object *l_outs_native = dap_get_remote_tx_outs(a_native_ticker, a_seller_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }

    json_object *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = dap_get_remote_tx_outs(a_price->token_sell, a_seller_addr, a_config);
    }
    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_count = json_object_array_length(l_outs);
#else
    json_object *l_outs = NULL;
    json_object *l_outs_native = NULL;
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
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            json_object_put(l_outs_native);
            if (dap_strcmp(a_price->token_sell, a_native_ticker))
                json_object_put(l_outs);
            DAP_DELETE(l_addr_net_fee);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_out_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    
    if (dap_strcmp(a_price->token_sell, a_native_ticker))
        json_object_put(l_outs);
    json_object_put(l_outs_native);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to transfer");
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
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
        return NULL;
    }
#endif
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
            DAP_DEL_Z(l_addr_net_fee);
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
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_CONDITIONAL_OUTPUT, "Can't compose the transaction conditional output");
            DAP_DEL_Z(l_addr_net_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output");
                DAP_DEL_Z(l_addr_net_fee);
                return NULL;
            }
        }
        DAP_DELETE(l_addr_net_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                log_it(L_ERROR, "Can't add validator's fee output");
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
                log_it(L_ERROR, "Can't add coin back output");
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
                    log_it(L_ERROR, "Can't add fee back output");
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
json_object* dap_tx_cond_create_compose(const char *a_net_name, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr,
                                        const char *a_cert_str, const char *a_value_datoshi_str, const char *a_value_fee_str,
                                        const char *a_unit_str, const char *a_value_per_unit_max_str,
                                        const char *a_srv_uid_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {    
    compose_config_t *l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
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
        log_it(L_ERROR, "Can't find service UID %s", a_srv_uid_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_SERVICE_UID, "Can't find service UID %s", a_srv_uid_str);
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)a_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        log_it(L_ERROR, "Can't recognize unit '%s'", a_unit_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT, "Can't recognize unit '%s'. Unit must look like { B | SEC }\n", a_unit_str);
        return s_compose_config_return_response_handler(l_config);
    }

    l_value_datoshi = dap_chain_balance_scan(a_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        log_it(L_ERROR, "Can't recognize value '%s' as a number", a_value_datoshi_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_datoshi_str);
        return s_compose_config_return_response_handler(l_config);
    }

    l_value_fee = dap_chain_balance_scan(a_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        log_it(L_ERROR, "Can't recognize fee value '%s' as a number", a_value_fee_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE, "Can't recognize value '%s' as a number\n", a_value_fee_str);
        return s_compose_config_return_response_handler(l_config);
    }
    if (a_value_per_unit_max_str)
        l_value_per_unit_max = dap_chain_balance_scan(a_value_per_unit_max_str);

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(a_cert_str);
    if(!l_cert_cond) {
        log_it(L_ERROR, "Can't find cert '%s'", a_cert_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND, "Can't find cert '%s'\n", a_cert_str);
        return s_compose_config_return_response_handler(l_config);
    }

    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        log_it(L_ERROR, "Cert '%s' doesn't contain a valid public key", a_cert_str);
        dap_json_compose_error_add(l_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY, "Cert '%s' doesn't contain a valid public key\n", a_cert_str);
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_mempool_tx_create_cond_compose(a_wallet_addr, l_key_cond, a_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_config);
    if (l_tx) {
        log_it_fl(L_DEBUG, "conditional transaction created successfully");
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create conditional transaction");
    }
    DAP_DELETE(l_key_cond);
    return s_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(dap_chain_addr_t *a_wallet_addr, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, compose_config_t *a_config)
{
    // check valid param
    
    dap_return_val_if_pass(!a_config->net_name || !*a_config->net_name || !a_key_cond || IS_ZERO_256(a_value) || !a_config->url_str || !*a_config->url_str || a_config->port == 0 || !a_wallet_addr, NULL);

    log_it_fl(L_DEBUG, "parameters validation passed");

    if (dap_strcmp(s_get_native_ticker(a_config->net_name), a_token_ticker)) {
        log_it(L_ERROR, "Pay for service should be only in native token_ticker");
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
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_wallet_addr, a_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "Failed to get remote wallet outputs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
#endif
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    json_object_put(l_outs);
    if(!l_list_used_out) {
        log_it(L_ERROR, "Nothing to transfer (not enough funds)");
        dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS, "Nothing to transfer (not enough funds)\n");
        DAP_DEL_Z(l_addr_fee);
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
            log_it(L_ERROR, "Can't add conditional output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_COND_CREATE_COMPOSE_ERROR_COND_OUTPUT_FAILED, "Cant add conditional output\n");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, a_token_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }
        DAP_DEL_Z(l_addr_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_token_ticker) != 1) {
                log_it(L_ERROR, "Can't add coin back output");
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

json_object * dap_cli_hold_compose(const char *a_net_name, const char *a_chain_id_str, const char *a_ticker_str, dap_chain_addr_t *a_wallet_addr, const char *a_coins_str, const char *a_time_staking_str,
                                    const char *a_cert_str, const char *a_value_fee_str, const char *a_reinvest_percent_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    
    compose_config_t *l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, CLI_HOLD_COMPOSE_ERROR_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }
    
    log_it_fl(L_DEBUG, "compose config initialized successfully");
    
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_enc_key_t						*l_key_from;
    dap_chain_addr_t					*l_addr_holder;
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value             =   {};

    json_object *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "ledger", "list;coins;-net;%s", l_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "Can't get coins");
        return s_compose_config_return_response_handler(l_config);
    }
    if (!check_token_in_ledger(l_json_coins, a_ticker_str)) {
        log_it(L_ERROR, "Invalid token '%s'", a_ticker_str);
        json_object_put(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TOKEN, "Invalid token '%s'\n", a_ticker_str);
        return s_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value = dap_chain_balance_scan(a_coins_str)))) {
        log_it(L_ERROR, "Invalid coins format '%s'", a_coins_str);
        json_object_put(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_COINS, "Invalid coins format\n");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, a_ticker_str);

    if (!check_token_in_ledger(l_json_coins, l_delegated_ticker_str)) {
        log_it(L_ERROR, "No delegated token found '%s'", l_delegated_ticker_str);
        json_object_put(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_NO_DELEGATED_TOKEN, "No delegated token found\n");
        return s_compose_config_return_response_handler(l_config);
    }
    json_object_put(l_json_coins);

    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");  // TODO 16126
    // uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);
    // if (IS_ZERO_256(l_emission_rate)) {
    //     printf("Error: Invalid token emission rate\n");
    //     return -8;
    // }

    if (MULT_256_COIN(l_value, l_emission_rate, &l_value_delegated) || IS_ZERO_256(l_value_delegated)) {
        log_it(L_ERROR, "Invalid emission rate");
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_EMISSION_RATE, "Invalid coins format\n");
        return s_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        log_it(L_ERROR, "Invalid fee format '%s'", a_value_fee_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_FEE, "Invalid fee format\n");
        return s_compose_config_return_response_handler(l_config);
    }

    if (dap_strlen(a_time_staking_str) != 6) {
        log_it(L_ERROR, "Invalid time staking format '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking format\n");
        return s_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_month_str[3] = {a_time_staking_str[2], a_time_staking_str[3], 0};
    int l_time_staking_month = atoi(l_time_staking_month_str);
    if (l_time_staking_month < 1 || l_time_staking_month > 12) {
        log_it(L_ERROR, "Invalid time staking month '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking month\n");
        return s_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_day_str[3] = {a_time_staking_str[4], a_time_staking_str[5], 0};
    int l_time_staking_day = atoi(l_time_staking_day_str);
    if (l_time_staking_day < 1 || l_time_staking_day > 31) {
        log_it(L_ERROR, "Invalid time staking day '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking day\n");
        return s_compose_config_return_response_handler(l_config);
    }

    l_time_staking = dap_time_from_str_simplified(a_time_staking_str);
    if (!l_time_staking) {
        log_it(L_ERROR, "Invalid time staking '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking\n");
        return s_compose_config_return_response_handler(l_config);
    }
    if (l_time_staking < dap_time_now()) {
        log_it(L_ERROR, "Time staking is in the past '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Time staking is in the past\n");
        return s_compose_config_return_response_handler(l_config);
    }

    if ( NULL != a_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_balance_coins_scan(a_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_balance_coins_scan("100.0")) == 1) {
            log_it(L_ERROR, "Invalid reinvest percentage '%s'", a_reinvest_percent_str);
            dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
            return s_compose_config_return_response_handler(l_config);
        }
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(a_reinvest_percent_str);
            if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100) {
                log_it(L_ERROR, "Invalid reinvest percentage '%s'", a_reinvest_percent_str);
                dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
                return s_compose_config_return_response_handler(l_config);
            }
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
    }
    
    json_object *l_json_outs = dap_request_command_to_rpc_with_params(l_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                       dap_chain_addr_to_str(a_wallet_addr), l_config->net_name);

    uint256_t l_value_balance = get_balance_from_json(l_json_outs, a_ticker_str);
    json_object_put(l_json_outs);
    if (compare256(l_value_balance, l_value) == -1) {
        log_it(L_ERROR, "Insufficient funds in wallet");
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INSUFFICIENT_FUNDS, "Insufficient funds in wallet\n");
        return s_compose_config_return_response_handler(l_config);
    }

    // Make transfer transaction
    dap_chain_datum_tx_t *l_tx = dap_stake_lock_datum_create_compose(a_wallet_addr,
                                                           a_ticker_str, l_value, l_value_fee,
                                                           l_time_staking, l_reinvest_percent,
                                                           l_delegated_ticker_str, l_value_delegated, a_chain_id_str, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return s_compose_config_return_response_handler(l_config);
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
    dap_return_val_if_pass(!a_config->net_name || !a_wallet_addr || IS_ZERO_256(a_value), NULL);
    log_it_fl(L_DEBUG, "parameters validation passed");
    
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t * l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address( &l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_list_t *l_list_fee_out = NULL;
    json_object *l_outs_native = NULL;
    json_object *l_outs_main = NULL;
    int l_out_main_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    if (!dap_strcmp(a_main_ticker, l_native_ticker)) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_get_remote_tx_outs(a_main_ticker, a_wallet_addr, a_config);
    }
    int l_out_native_count = json_object_array_length(l_outs_native);
    l_out_main_count = json_object_array_length(l_outs_main);

    if (l_main_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs_main);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
    }
#endif
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        json_object_put(l_outs_native);
        json_object_put(l_outs_main);
        DAP_DEL_Z(l_addr_fee);
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
        DAP_DEL_Z(l_in_ems);
    }

    // add 'out_cond' and 'out_ext' items
    {
        uint256_t l_value_pack = {}, l_native_pack = {}; // how much coin add to 'out_ext' items
        dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(l_uid, a_value, a_time_unlock, a_reinvest_percent);
        if (l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond);
            DAP_DEL_Z(l_tx_out_cond);
        } else {
            log_it(L_ERROR, "Can't add conditional output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_CONDITIONAL_OUTPUT, "Cant add conditional output\n");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }

        uint256_t l_value_back = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_NETWORK_FEE_OUTPUT, "Cant add network fee output\n");
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
            if (l_main_native)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else
                SUM_256_256(l_native_pack, l_net_fee, &l_native_pack);
        }
        DAP_DEL_Z(l_addr_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                log_it(L_ERROR, "Can't add validator's fee output");
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
                log_it(L_ERROR, "Can't add coin back output for main ticker");
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
                    log_it(L_ERROR, "Can't add coin back output for native ticker");
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_NATIVE_TICKER, "Cant add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add delegated token emission 'out_ext'
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_delegated_value, a_delegated_ticker_str) != 1) {
        log_it(L_ERROR, "Can't add delegated token emission output");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_DELEGATED_TOKEN_EMISSION_OUTPUT, "Cant add delegated token emission output\n");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    DAP_DELETE(l_addr_fee);
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
    dap_chain_tx_out_cond_t **a_cond_tx, char **a_spent_by_hash, 
    char **a_token_ticker, int *a_out_idx)
{
    json_object *l_raw_response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s;-tx_to_json", 
                                                                      a_tx_str, a_config->net_name);
    if (!l_raw_response) {
        log_it(L_ERROR, "Failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return NULL;
    }

    json_object *l_response = json_object_array_get_idx(l_raw_response, 0);
    if (!l_response) {
        log_it(L_ERROR, "No items found in response");
        json_object_put(l_raw_response);
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND, "No items found in response\n");
        return NULL;
    }
    json_object_get(l_response);
    json_object_put(l_raw_response);
    dap_chain_datum_tx_t *l_datum = dap_chain_datum_tx_create();
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    json_object * l_json_errors = json_object_new_array();
    if (dap_chain_tx_datum_from_json(l_response, NULL, l_json_errors, &l_datum, &l_items_count, &l_items_ready) || l_items_count != l_items_ready) {
        log_it(L_ERROR, "Failed to create transaction from json");
        json_object_put(l_response);
        dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_FAILED_TO_CREATE_TX, "Failed to create transaction from json\n");
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
            json_object_put(l_response);
            dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND, "No transaction output condition found\n");
            dap_chain_datum_tx_delete(l_datum);
            return NULL;
        }
        if (a_spent_by_hash) {
            DAP_DEL_Z(*a_spent_by_hash);
            json_object *l_spent_outs = json_object_object_get(l_response, "spent_outs");
            size_t l_spent_outs_count = l_spent_outs ? json_object_array_length(l_spent_outs) : 0;
            for (size_t i = 0; i < l_spent_outs_count; i++) {
                json_object *l_spent_out_json = json_object_array_get_idx(l_spent_outs, i);
                json_object *l_out_idx_json = json_object_object_get(l_spent_out_json, "out_idx");
                if (l_out_idx_json && json_object_get_int(l_out_idx_json) == l_out_idx) {
                    const char *l_spent_by_tx = json_object_get_string(json_object_object_get(l_spent_out_json, "spent_by_tx"));
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
        json_object *l_token_ticker = json_object_object_get(l_response, "token_ticker");
        if (!l_token_ticker) {
            log_it(L_ERROR, "Token ticker not found in response");
            json_object_put(l_response);
            dap_json_compose_error_add(a_config->response_handler, CLI_TAKE_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND, "Token ticker not found in response\n");
            return NULL;
        }
        *a_token_ticker = dap_strdup(json_object_get_string(l_token_ticker));
    }
    json_object_put(l_response);
    return l_datum;
}

json_object* dap_cli_take_compose(const char *a_net_name, const char *a_chain_id_str, dap_chain_addr_t *a_wallet_addr, const char *a_tx_str,
                                    const char *a_value_fee_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path){

    compose_config_t * l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Unable to init config");
        json_object * l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG, "Unable to init config\n");
        return l_json_obj_ret;
    }

    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    int									l_prev_cond_idx		=	0;
    uint256_t							l_value_delegated	= 	{};
    uint256_t                           l_value_fee     	=	{};
    dap_hash_fast_t						l_tx_hash;
    dap_chain_datum_tx_t                *l_tx = NULL;
    dap_chain_tx_out_cond_t				*l_cond_tx = NULL;
    dap_enc_key_t						*l_owner_key;
    char *l_ticker_str = NULL;
    if (dap_chain_hash_fast_from_str(a_tx_str, &l_tx_hash)) {
        log_it(L_ERROR, "Invalid transaction hash");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_TRANSACTION_HASH, "Invalid transaction hash\n");
        return s_compose_config_return_response_handler(l_config);
    }

    l_tx = s_get_datum_info_from_rpc(a_tx_str, l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_cond_tx, NULL, &l_ticker_str, NULL);
    if (!l_cond_tx) {
        log_it(L_ERROR, "Failed to get datum info from rpc");
        DAP_DELETE(l_ticker_str);
        return s_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);
    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");

    if (IS_ZERO_256(l_emission_rate) ||
        MULT_256_COIN(l_cond_tx->header.value, l_emission_rate, &l_value_delegated) ||
        IS_ZERO_256(l_value_delegated)) {
        log_it(L_ERROR, "Invalid coins format");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_COINS_FORMAT, "Invalid coins format\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return s_compose_config_return_response_handler(l_config);
    }

    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        log_it(L_ERROR, "Invalid fee format");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_FEE_FORMAT, "Invalid fee format\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return s_compose_config_return_response_handler(l_config);
    }

    if (l_cond_tx->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        log_it(L_ERROR, "Not enough time has passed for unlocking");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED, "Not enough time has passed for unlocking\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return s_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_delete(l_tx);
    l_tx = dap_stake_unlock_datum_create_compose(a_wallet_addr, &l_tx_hash, l_prev_cond_idx,
                                          l_ticker_str, l_cond_tx->header.value, l_value_fee,
                                          l_delegated_ticker_str, l_value_delegated, l_config);

    DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return s_compose_config_return_response_handler(l_config);
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
        log_it(L_ERROR, "Invalid parameters");
        dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_INVALID_PARAMS, "Invalid parameters\n");
        return NULL;
    }

    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t* l_addr_fee = NULL;

    dap_list_t *l_list_fee_out = NULL, *l_list_used_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    json_object *l_outs_delegated = dap_get_remote_tx_outs(a_delegated_ticker_str, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_delegated_count = json_object_array_length(l_outs_delegated);
#else
    json_object *l_outs_native = NULL;
    json_object *l_outs_delegated = NULL;
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
                log_it(L_ERROR, "Not enough funds to pay fee");
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
                json_object_put(l_outs_native);
                json_object_put(l_outs_delegated);
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        else if (compare256(a_value, l_total_fee) == -1) {
            log_it(L_ERROR, "Total fee more than stake");
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_TOTAL_FEE_MORE_THAN_STAKE, "Total fee more than stake\n");
            json_object_put(l_outs_native);
            json_object_put(l_outs_delegated);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
#endif
    }
    if (!IS_ZERO_256(a_delegated_value)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_delegated_value, 
                                                               &l_value_transfer);
        if (!l_list_used_out) {
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs_delegated);
            DAP_DEL_Z(l_addr_fee);
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
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output\n");
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        }
        DAP_DEL_Z(l_addr_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
            {
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            } else {
                log_it(L_ERROR, "Can't add validator's fee output");
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
                    log_it(L_ERROR, "Can't add coin back output for main ticker");
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
            } else {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker)!=1) {
                    log_it(L_ERROR, "Can't add coin back output for native ticker");
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
            log_it(L_ERROR, "Can't add burning output for delegated value");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_BURNING_OUTPUT, "Can't add burning output for delegated value\n");
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, a_delegated_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_delegated_ticker_str) != 1) {
                log_it(L_ERROR, "Can't add coin back output for delegated ticker");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_UNLOCK_COMPOSE_CANT_ADD_COIN_BACK_DELEGATED, "Can't add coin back output for delegated ticker\n");
                return NULL;
            }
        }
    }
    DAP_DELETE(l_addr_fee);
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

    log_it_fl(L_DEBUG, "getting key delegating min value for net %s", a_config->net_name);
    
    uint256_t l_key_delegating_min_value = uint256_0;
    json_object *response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "list;keys;-net;%s", a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "Failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return l_key_delegating_min_value;
    }

    json_object *response_array = json_object_array_get_idx(response, 0);
    if (!response_array) {
        log_it(L_ERROR, "Invalid response format");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_RESPONSE_FORMAT, "Invalid response format\n");
        return l_key_delegating_min_value;
    }

    json_object *summary_obj = json_object_array_get_idx(response_array, json_object_array_length(response_array) - 1);
    if (!summary_obj) {
        log_it(L_ERROR, "Summary object not found in response");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_SUMMARY_NOT_FOUND, "Summary object not found in response\n");
        return l_key_delegating_min_value;
    }

    json_object *key_delegating_min_value_obj = json_object_object_get(summary_obj, "key_delegating_min_value");
    if (!key_delegating_min_value_obj) {
        log_it(L_ERROR, "Key delegating min value not found in summary");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_MIN_VALUE_NOT_FOUND, "Key delegating min value not found in summary\n");
        return l_key_delegating_min_value;
    }

    const char *key_delegating_min_value_str = json_object_get_string(key_delegating_min_value_obj);
    if (!key_delegating_min_value_str) {
        log_it(L_ERROR, "Invalid key_delegating_min_value format");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_VALUE_FORMAT, "Invalid key_delegating_min_value format\n");
        return l_key_delegating_min_value;
    }

    l_key_delegating_min_value = dap_chain_balance_scan(key_delegating_min_value_str);
    if (IS_ZERO_256(l_key_delegating_min_value)) {
        log_it(L_ERROR, "Unrecognized number in key_delegating_min_value");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_UNRECOGNIZED_NUMBER, "Unrecognized number in key_delegating_min_value\n");
        return l_key_delegating_min_value;
    }

    return l_key_delegating_min_value;
}



json_object* dap_cli_voting_compose(const char *a_net_name, const char *a_question_str, const char *a_options_list_str, 
                                    const char *a_voting_expire_str, const char *a_max_votes_count_str, const char *a_fee_str, 
                                    bool a_is_delegated_key, bool a_is_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr, const char *a_token_str, 
                                    const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    
    compose_config_t * l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Unable to init config");
        json_object * l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG, "Unable to init config\n");
        return l_json_obj_ret;
    }
    
    log_it_fl(L_DEBUG, "Compose config initialized successfully");
    
    if (strlen(a_question_str) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        log_it(L_ERROR, "Question too long");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH, "The question must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        return s_compose_config_return_response_handler(l_config);
    }

    dap_list_t *l_options_list = NULL;
    // Parse options list
    l_options_list = dap_get_options_list_from_str(a_options_list_str);
    if(!l_options_list || dap_list_length(l_options_list) < 2){
        log_it(L_ERROR, "Number of options must be 2 or greater");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR, "Number of options must be 2 or greater.\n");
        return s_compose_config_return_response_handler(l_config);
    }

    if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
        log_it(L_ERROR, "Number of options must be less than %d", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS, "The voting can contain no more than %d options\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);            
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_value_fee = dap_chain_balance_scan(a_fee_str);


    dap_time_t l_time_expire = 0;
    if (a_voting_expire_str)
        l_time_expire = dap_time_from_str_rfc822(a_voting_expire_str);
    if (a_voting_expire_str && !l_time_expire){
        log_it(L_ERROR, "Wrong time format");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT, "Wrong time format. -expire parameter must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"\n");
        return s_compose_config_return_response_handler(l_config);
    }
    uint64_t l_max_count = 0;
    if (a_max_votes_count_str)
        l_max_count = strtoul(a_max_votes_count_str, NULL, 10);
        
    json_object *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "ledger", "list;coins;-net;%s", l_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "Can't get ledger coins list");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get ledger coins list\n");
        return s_compose_config_return_response_handler(l_config);
    }
    if (!check_token_in_ledger(l_json_coins, a_token_str)) {
        log_it(L_ERROR, "Token does not exist");
        json_object_put(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN, "Token %s does not exist\n", a_token_str);
        return s_compose_config_return_response_handler(l_config);
    }
    json_object_put(l_json_coins);

    dap_chain_datum_tx_t* l_tx = dap_chain_net_vote_create_compose(a_question_str, l_options_list, l_time_expire, l_max_count,
                                                                l_value_fee, a_is_delegated_key, a_is_vote_changing_allowed, 
                                                                a_wallet_addr, a_token_str, l_config);
    dap_list_free(l_options_list);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    return s_compose_config_return_response_handler(l_config);
}

typedef enum {
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_OK = 0,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_CONFIG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_QUESTION_TOO_LONG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOO_MANY_OPTIONS,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_ZERO_FEE,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_WALLET_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_TOO_LONG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_EXPIRE_TIME,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_EXPIRE_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_MAX_VOTES_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_DELEGATED_KEY_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_VOTE_CHANGING_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOKEN_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_FEE_OUTPUT_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_COINBACK_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_NOT_ENOUGH_FUNDS
} dap_chain_net_vote_create_compose_error_t;

dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr,
                              const char *a_token_ticker, compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config, NULL);

    if (strlen(a_question) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        log_it(L_ERROR, "Question too long");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_QUESTION_TOO_LONG, "The question must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        return NULL;
    }

    // Parse options list

    if(dap_list_length(a_options) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT) {
        log_it(L_ERROR, "Too many options");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOO_MANY_OPTIONS, "The voting can contain no more than %d options\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
        return NULL;
    }

    if (IS_ZERO_256(a_fee)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_ZERO_FEE, "Fee must be greater than 0\n");
        return NULL;
    }

    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
    uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);


    dap_chain_addr_t *l_addr_from = NULL;
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    l_addr_from = a_wallet_addr;
    if(!l_addr_from) {
        log_it(L_ERROR, "Wallet does not exist");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_WALLET_NOT_FOUND, "Wallet does not exist\n");
        DAP_DEL_Z(l_addr_from);
        return NULL;
    }
    if (!dap_get_remote_wallet_outs_and_count(l_addr_from, l_native_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "Can't get remote wallet outputs");
        DAP_DEL_Z(l_addr_from);
        return NULL;
    }
#else
    l_addr_from = a_wallet_addr;
#endif


    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer);

    json_object_put(l_outs);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_NOT_ENOUGH_FUNDS, "Not enough funds to transfer");
        DAP_DEL_Z(l_addr_from);
        return NULL;
    }


    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Add Voting item
    dap_chain_tx_voting_t* l_voting_item = dap_chain_datum_tx_item_voting_create();

    dap_chain_datum_tx_add_item(&l_tx, l_voting_item);
    DAP_DELETE(l_voting_item);

    // Add question to tsd data
    dap_chain_tx_tsd_t* l_question_tsd = dap_chain_datum_voting_question_tsd_create(a_question, strlen(a_question));
    dap_chain_datum_tx_add_item(&l_tx, l_question_tsd);
    DAP_DEL_Z(l_question_tsd);

    // Add options to tsd
    dap_list_t *l_temp = a_options;
    while(l_temp){
        if(strlen((char*)l_temp->data) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH){
            log_it(L_ERROR, "Option too long");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_TOO_LONG, "The option must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH);
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_tx_tsd_t* l_option = dap_chain_datum_voting_answer_tsd_create((char*)l_temp->data, strlen((char*)l_temp->data));
        if(!l_option){
            log_it(L_ERROR, "Failed to create option");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_CREATE_FAILED, "Failed to create option\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_option);
        DAP_DEL_Z(l_option);

        l_temp = l_temp->next;
    }

    // add voting expire time if needed
    if(a_expire_vote != 0){
        dap_time_t l_expired_vote = a_expire_vote;
        if (l_expired_vote < dap_time_now()){
            log_it(L_ERROR, "Expire time must be in the future");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_EXPIRE_TIME, "Expire time must be in the future\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }

        dap_chain_tx_tsd_t* l_expired_item = dap_chain_datum_voting_expire_tsd_create(l_expired_vote);
        if(!l_expired_item){
            log_it(L_ERROR, "Failed to create expire time item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_EXPIRE_CREATE_FAILED, "Failed to create expire time item\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_expired_item);
        DAP_DEL_Z(l_expired_item);
    }

    // Add vote max count if needed
    if (a_max_vote != 0) {
        dap_chain_tx_tsd_t* l_max_votes_item = dap_chain_datum_voting_max_votes_count_tsd_create(a_max_vote);
        if(!l_max_votes_item){
            log_it(L_ERROR, "Failed to create max votes item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_MAX_VOTES_CREATE_FAILED, "Failed to create max votes item\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_max_votes_item);
        DAP_DEL_Z(l_max_votes_item);
    }

    if (a_delegated_key_required) {
        dap_chain_tx_tsd_t* l_delegated_key_req_item = dap_chain_datum_voting_delegated_key_required_tsd_create(true);
        if(!l_delegated_key_req_item){
            log_it(L_ERROR, "Failed to create delegated key requirement item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_DELEGATED_KEY_CREATE_FAILED, "Failed to create delegated key requirement item\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_delegated_key_req_item);
        DAP_DEL_Z(l_delegated_key_req_item);
    }

    if(a_vote_changing_allowed){
        dap_chain_tx_tsd_t* l_vote_changing_item = dap_chain_datum_voting_vote_changing_allowed_tsd_create(true);
        if(!l_vote_changing_item){
            log_it(L_ERROR, "Failed to create vote changing item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_VOTE_CHANGING_CREATE_FAILED, "Failed to create vote changing item\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_vote_changing_item);
        DAP_DEL_Z(l_vote_changing_item);
    }
    if (a_token_ticker) {
        dap_chain_tx_tsd_t *l_voting_token_item = dap_chain_datum_voting_token_tsd_create(a_token_ticker);
        if (!l_voting_token_item) {
            log_it(L_ERROR, "Failed to create token item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOKEN_CREATE_FAILED, "Failed to create token item\n");
            DAP_DEL_Z(l_addr_from);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_voting_token_item);
        DAP_DEL_Z(l_voting_token_item);
    }

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
    dap_list_free_full(l_list_used_out, NULL);
    uint256_t l_value_pack = {};
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) == 1)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        else {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
    }
    DAP_DEL_Z(l_addr_fee);
    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            log_it(L_ERROR, "Can't add fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_FEE_OUTPUT_FAILED, "Can't add fee output in tx");
            return NULL;
        }
    }
    // coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add coin back output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_COINBACK_FAILED, "Can't add coin back in tx");
            return NULL;
        }
    }
    return l_tx;
}

typedef enum {
    DAP_CLI_VOTE_COMPOSE_OK = 0,
    DAP_CLI_VOTE_COMPOSE_INVALID_CONFIG = -1,
    DAP_CLI_VOTE_COMPOSE_INVALID_HASH = -2,
    DAP_CLI_VOTE_COMPOSE_CERT_NOT_FOUND = -3,
    DAP_CLI_VOTE_COMPOSE_INVALID_FEE = -4,
    DAP_CLI_VOTE_COMPOSE_WALLET_NOT_FOUND = -5
} dap_cli_vote_compose_error_t;

json_object* dap_cli_vote_compose(const char *a_net_str, const char *a_hash_str, const char *a_cert_name, const char *a_fee_str, dap_chain_addr_t *a_wallet_addr, 
                                    const char *a_option_idx_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    compose_config_t *l_config = s_compose_config_init(a_net_str, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, DAP_CLI_VOTE_COMPOSE_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    dap_hash_fast_t l_voting_hash = {};
    if (dap_chain_hash_fast_from_str(a_hash_str, &l_voting_hash)) {
        log_it(L_ERROR, "Hash string is not recognized as hex of base58 hash");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_INVALID_HASH, "Hash string is not recognozed as hex of base58 hash\n");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_cert_t * l_cert = dap_cert_find_by_name(a_cert_name);
    if (a_cert_name && !l_cert) {
        log_it(L_ERROR, "Can't find certificate");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_CERT_NOT_FOUND, "Can't find \"%s\" certificate\n", a_cert_name);
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_value_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_value_fee)) {
        log_it(L_ERROR, "Invalid fee");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_INVALID_FEE, "command requires parameter '-fee' to be valid uint256\n");            
        return s_compose_config_return_response_handler(l_config);
    }

    uint64_t l_option_idx_count = strtoul(a_option_idx_str, NULL, 10);

    dap_chain_datum_tx_t *l_tx = dap_chain_net_vote_voting_compose(l_cert, l_value_fee, a_wallet_addr, l_voting_hash, l_option_idx_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    return s_compose_config_return_response_handler(l_config);
}


static bool s_datum_tx_voting_coin_check_spent_compose(json_object *a_votes_list, dap_hash_fast_t a_tx_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash) {
    dap_return_val_if_pass(!a_votes_list, false);

    size_t l_votes_count = json_object_array_length(a_votes_list);
    log_it_fl(L_DEBUG, "Сhecking %zu votes", l_votes_count);

    for (size_t i = 0; i < l_votes_count; i++) {
        json_object *l_vote = json_object_array_get_idx(a_votes_list, i);
        const char *l_vote_hash = json_object_get_string(json_object_object_get(l_vote, "vote_hash")),
                *l_pkey_hash = json_object_get_string(json_object_object_get(l_vote, "pkey_hash"));
        if (!dap_strcmp(l_vote_hash, dap_chain_hash_fast_to_str_static(&a_tx_hash)) && a_out_idx == json_object_get_int(json_object_object_get(l_vote, "answer_idx"))) {
            log_it_fl(L_DEBUG, "Found matching vote at index %zu", i);
            return a_pkey_hash ? !dap_strcmp(l_pkey_hash, dap_chain_hash_fast_to_str_static(a_pkey_hash)) : true;
        }
    }
    log_it_fl(L_DEBUG, "No matching vote found");
    return false;
}
typedef enum {
    DAP_CHAIN_NET_VOTE_COMPOSE_OK = 0,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_FIND_CERT = -1,
    DAP_CHAIN_NET_VOTE_COMPOSE_FEE_PARAM_BAD_TYPE = -2,
    DAP_CHAIN_NET_VOTE_COMPOSE_WALLET_DOES_NOT_EXIST = -3,
    DAP_CHAIN_NET_VOTE_COMPOSE_SOURCE_ADDRESS_INVALID = -4,
    DAP_CHAIN_NET_VOTE_COMPOSE_CERT_REQUIRED = -5,
    DAP_CHAIN_NET_VOTE_COMPOSE_NO_KEY_FOUND_IN_CERT = -6,
    DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER = -7,
    DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED = -8,
    DAP_CHAIN_NET_VOTE_COMPOSE_NOT_ENOUGH_FUNDS_TO_TRANSFER = -9,
    DAP_CHAIN_NET_VOTE_COMPOSE_INTEGER_OVERFLOW = -10,
    DAP_CHAIN_NET_VOTE_COMPOSE_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING = -11,
    DAP_CHAIN_NET_VOTE_COMPOSE_INVALID_OPTION_INDEX = -12,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_CREATE_VOTE_ITEM = -13,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_GET_STAKE_LIST = -14,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_CREATE_TSD_TX_COND_ITEM = -15,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_ADD_NET_FEE_OUT = -16,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK = -17,
    DAP_CHAIN_NET_VOTE_COMPOSE_THIS_VOTING_HAVE_MAX_VALUE_VOTES = -18,
    DAP_CHAIN_NET_VOTE_COMPOSE_ALREADY_EXPIRED = -19,
    DAP_CHAIN_NET_VOTE_COMPOSE_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE = -20,
    DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS = -21,
    DAP_CHAIN_NET_VOTE_COMPOSE_ERR_NOT_ENOUGH_FUNDS = -22,
    DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_GET_REMOTE_WALLET_OUTS = -23
} dap_chain_net_vote_compose_error_t;

dap_chain_datum_tx_t* dap_chain_net_vote_voting_compose(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, dap_hash_fast_t a_hash,
                              uint64_t a_option_idx, compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    const char * l_hash_str = dap_chain_hash_fast_to_str_static(&a_hash);

    json_object *l_json_voting = dap_request_command_to_rpc_with_params(a_config, "poll", "dump;-need_vote_list;-net;%s;-hash;%s", 
                                                                      a_config->net_name, l_hash_str);
    if (!l_json_voting) {
        log_it(L_ERROR, "Can't get voting info");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting info\n");
        return NULL;
    }

    
    json_object *l_voting_info = json_object_array_get_idx(l_json_voting, 0);
    if (!l_voting_info) {
        log_it(L_ERROR, "Can't get voting info from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting info from JSON\n");
        return NULL;
    }

    const char *l_voting_tx = json_object_get_string(json_object_object_get(l_voting_info, "voting_tx"));
    const char *l_expiration_str = json_object_get_string(json_object_object_get(l_voting_info, "expiration"));
    const char *l_status = json_object_get_string(json_object_object_get(l_voting_info, "status"));
    int l_votes_max = json_object_get_int(json_object_object_get(l_voting_info, "votes_max"));
    int l_votes_available = json_object_get_int(json_object_object_get(l_voting_info, "votes_available"));
    bool l_vote_changed = json_object_get_boolean(json_object_object_get(l_voting_info, "can_change_status"));
    bool l_delegated_key_required = json_object_get_boolean(json_object_object_get(l_voting_info, "delegated_key_required"));
    char l_token_ticker[10] = {0};
    dap_stpcpy(l_token_ticker, json_object_get_string(json_object_object_get(l_voting_info, "token")));

    json_object *l_options = json_object_object_get(l_voting_info, "results");
    if (!l_options) {
        log_it(L_ERROR, "Can't get options from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get options from JSON\n");
        return NULL;
    }

    uint64_t l_options_count = json_object_array_length(l_options);
    if (a_option_idx >= l_options_count) {
        log_it(L_ERROR, "Invalid option index");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_INVALID_OPTION_INDEX, "Invalid option index\n");
        return NULL;
    }


    json_object *l_results = json_object_object_get(l_voting_info, "results");
    if (!l_results) {
        log_it(L_ERROR, "Can't get results from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get results from JSON\n");
        return NULL;
    }

    int l_results_count = json_object_array_length(l_results);


    if (l_votes_max && l_votes_max <= l_results_count) {
        log_it(L_ERROR, "This voting have max value votes");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_THIS_VOTING_HAVE_MAX_VALUE_VOTES, "This voting have max value votes\n");
        return NULL;
    }

    if (l_expiration_str) {
        struct tm tm;
        strptime(l_expiration_str, "%a, %d %b %Y %H:%M:%S %z", &tm);
        dap_time_t l_expiration_time = mktime(&tm);
        if (l_expiration_time && dap_time_now() > l_expiration_time) {
            log_it(L_ERROR, "This voting already expired");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ALREADY_EXPIRED, "This voting already expired\n");
            return NULL;
        }
    }
    dap_hash_fast_t l_pkey_hash = {0};
#else
    dap_hash_fast_t l_pkey_hash = a_wallet_addr->data.hash_fast;
    char l_token_ticker[10] = "vBUZ"; // todo: remove this
    bool l_delegated_key_required = false;
#endif
    if (l_delegated_key_required) {
        if (!a_cert) {
            log_it(L_ERROR, "Certificate is required for delegated key voting");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_CERT_REQUIRED, "Certificate is required for delegated key voting\n");
            return NULL;
        }
        if (dap_cert_get_pkey_hash(a_cert, &l_pkey_hash)) {
            log_it(L_ERROR, "No key found in certificate");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_NO_KEY_FOUND_IN_CERT, "No key found in certificate\n");
            return NULL;
        }

        json_object *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "list;keys;-net;%s", a_config->net_name);
        if (!l_json_coins) {
            log_it(L_ERROR, "Failed to retrieve coins from ledger");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER, "Failed to retrieve coins from ledger\n");
            return NULL;
        }

        char l_hash_fast_str[DAP_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_pkey_hash, l_hash_fast_str, sizeof(l_hash_fast_str));
        if (strlen(l_hash_fast_str) == 0) {
            log_it(L_ERROR, "Can't convert l_pkey_hash to str");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER, "Can't covert l_pkey_hash to str");
            return NULL;
        }
        int items_count = json_object_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            json_object *item = json_object_array_get_idx(l_json_coins, i);
            const char *pkey_hash_str = json_object_get_string(json_object_object_get(item, "pkey_hash"));
            if (!dap_strcmp(l_hash_fast_str, pkey_hash_str)) {
                const char *tx_hash_str = json_object_get_string(json_object_object_get(item, "tx_hash"));
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_pkey_hash)) {
                    log_it(L_ERROR, "Invalid transaction hash format");
                    dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED, "Invalid transaction hash format\n");
                    return NULL;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            log_it(L_ERROR, "Specified certificate/pkey hash is not delegated nor this delegating is approved");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED, 
                                            "Specified certificate/pkey hash is not delegated nor this delegating is approved. Try to invalidate with tx hash instead\n");
            return NULL;
        }


    } else
        l_pkey_hash = a_wallet_addr->data.hash_fast;



    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_value_transfer, l_fee_transfer;
    dap_chain_addr_t* l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    bool l_native_tx = !dap_strcmp(l_token_ticker, s_get_native_ticker(a_config->net_name));

    json_object *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if (!dap_get_remote_wallet_outs_and_count(a_wallet_addr, l_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "Failed to get remote wallet outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_GET_REMOTE_WALLET_OUTS, "Failed to get remote wallet outs\n");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
#endif

    // todo replace with func witch will return all outpurs not only enough outputs
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json_all(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer);
    json_object_put(l_outs);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    uint256_t l_value_transfer_new = {};
    int l_votes_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    json_object *l_votes_list = json_object_object_get(l_voting_info, "votes_list");
    if (!l_votes_list) { 
        log_it(L_ERROR, "Can't get voting list");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting list\n");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    if (json_object_is_type(l_votes_list, json_type_array)) {
        l_votes_count = json_object_array_length(l_votes_list);
    } else {
        l_votes_count = 0;
    }

    for (int i = 0; i < l_votes_count; i++) {
        json_object *l_vote = json_object_array_get_idx(l_votes_list, i);
        const char *l_vote_pkey_hash = json_object_get_string(json_object_object_get(l_vote, "pkey_hash"));
        char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, sizeof(l_pkey_hash_str));
        if (!dap_strcmp(l_vote_pkey_hash, l_pkey_hash_str)) {
            if (!l_vote_changed) {
                log_it(L_ERROR, "The poll doesn't allow change your vote");
                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE, "The poll doesn't allow change your vote.");
                json_object_put(l_json_voting);
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }
    }
    json_object_get(l_votes_list);
    json_object_put(l_json_voting);

    if (l_votes_count > 0) {
        dap_list_t *it, *tmp;
        DL_FOREACH_SAFE(l_list_used_out, it, tmp) {
            dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)it->data;
            if (s_datum_tx_voting_coin_check_spent_compose(l_votes_list, l_out->tx_hash_fast, l_out->num_idx_out,
                                                l_vote_changed ? &l_pkey_hash : NULL)) {
                l_list_used_out = dap_list_delete_link(l_list_used_out, it);
                continue;
            }
            if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new)) {
                log_it(L_ERROR, "Failed to sum value");
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }
        if (IS_ZERO_256(l_value_transfer_new) || (l_native_tx && compare256(l_value_transfer_new, l_total_fee) <= 0)) {
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        l_value_transfer = l_value_transfer_new;
    }
#else
    randombytes(&l_value_transfer_new, sizeof(l_value_transfer_new));
#endif


    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    uint256_t l_value_back = l_value_transfer, l_fee_back = {};
    if (!l_native_tx) {
        dap_list_t * l_list_fee_outs = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_outs) {
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
            json_object_put(l_outs);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }

        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_outs);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
#endif
        dap_list_free_full(l_list_fee_outs, NULL);
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
    } else
        SUBTRACT_256_256(l_value_transfer, l_total_fee, &l_value_back);

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
    dap_list_free_full(l_list_used_out, NULL);

    dap_chain_tx_vote_t* l_vote_item = dap_chain_datum_tx_item_vote_create(&a_hash, &a_option_idx);
    if(!l_vote_item){
        log_it(L_ERROR, "Failed to create vote item");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
    json_object *l_cond_tx_outputs_raw = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-net;%s;-token;%s;-cond;-mempool_check",
                                                                            dap_chain_addr_to_str(a_wallet_addr), a_config->net_name, l_token_ticker);
    if (!l_cond_tx_outputs_raw) {
        log_it(L_ERROR, "Failed to get cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    if (!json_object_is_type(l_cond_tx_outputs_raw, json_type_array)) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_cond_tx_outputs_raw);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    json_object *l_first_array = json_object_array_get_idx(l_cond_tx_outputs_raw, 0);
    if (!l_first_array || !json_object_is_type(l_first_array, json_type_array)) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_cond_tx_outputs_raw);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    json_object *l_first_item = json_object_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_cond_tx_outputs_raw);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    json_object *l_cond_tx_outputs = NULL;
    json_object_object_get_ex(l_first_item, "outs", &l_cond_tx_outputs);
    if (!l_cond_tx_outputs) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_cond_tx_outputs_raw);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    size_t l_cond_outputs_count = json_object_array_length(l_cond_tx_outputs);

    dap_list_t *l_cond_outs = dap_ledger_get_list_tx_outs_from_json_all(l_cond_tx_outputs, l_cond_outputs_count,
                                                            l_total_fee,    
                                                            &l_value_transfer);
    for (dap_list_t *it = l_cond_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)it->data;
        if (l_votes_count > 0) { 
            if (s_datum_tx_voting_coin_check_spent_compose(l_votes_list, l_out_item->tx_hash_fast, l_out_item->num_idx_out,
                                                    l_vote_changed ? &l_pkey_hash : NULL) != 0)
                continue;
        }
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if(!l_item){
            log_it(L_ERROR, "Failed to create cond tx tsd");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_addr_fee);
            dap_list_free_full(l_cond_outs, NULL);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_item);
        DAP_DEL_Z(l_item);
    }
    dap_list_free_full(l_cond_outs, NULL);
#endif
    // Network fee
    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, s_get_native_ticker(a_config->net_name)) != 1) {
        log_it(L_ERROR, "Failed to add network fee output");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    DAP_DEL_Z(l_addr_fee);
    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        log_it(L_ERROR, "Failed to add fee output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // coin back
    if (!IS_ZERO_256(l_value_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add coin back output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_fee_back, s_get_native_ticker(a_config->net_name)) != 1) {
        log_it(L_ERROR, "Failed to add coin back output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    return l_tx;
}




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
    DAP_CLI_STAKE_INVALIDATE_KEY_DELEGATED = -9,
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
json_object* dap_cli_srv_stake_invalidate_compose(const char *a_net_str, const char *a_tx_hash_str, dap_chain_addr_t *a_wallet_addr, 
                                                  const char *a_cert_str, const char *a_fee_str, const char *a_url_str, uint16_t a_port, const char *a_cert_path)
{
    compose_config_t* l_config = s_compose_config_init(a_net_str, a_url_str, a_port, a_cert_path);
    dap_hash_fast_t l_tx_hash = {};

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "Unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_FEE_ERROR, "Unrecognized number in '-fee' param");
        return s_compose_config_return_response_handler(l_config);
    }

    if (a_tx_hash_str) {
        dap_chain_hash_fast_from_str(a_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        if (a_cert_str) {
            dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_str);
            if (!l_cert) {
                log_it(L_ERROR, "Specified certificate not found");
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_CERT_NOT_FOUND, "Specified certificate not found");
                return s_compose_config_return_response_handler(l_config);
            }
            if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
                log_it(L_ERROR, "Private key missing in certificate");
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_PRIVATE_KEY_MISSING, "Private key missing in certificate");
                return s_compose_config_return_response_handler(l_config);
            }
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, dap_get_net_id(a_net_str))) {
                log_it(L_ERROR, "Wrong certificate");
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_WRONG_CERT, "Wrong certificate");
                return s_compose_config_return_response_handler(l_config);
            }
        }
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_signing_addr);

        json_object *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;keys;-net;%s", l_config->net_name);
        if (!l_json_coins) {
            log_it(L_ERROR, "Failed to get coins list");
            return s_compose_config_return_response_handler(l_config);
        }
        
        int items_count = json_object_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            json_object *item = json_object_array_get_idx(l_json_coins, i);
            const char *node_addr_str = json_object_get_string(json_object_object_get(item, "node_addr"));
            if (node_addr_str && !dap_strcmp(l_addr_str, node_addr_str)) {
                const char *tx_hash_str = json_object_get_string(json_object_object_get(item, "tx_hash"));
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_tx_hash)) {
                    log_it(L_ERROR, "Invalid transaction hash format");
                    json_object_put(l_json_coins);
                    dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_INVALID_TX_HASH, "Invalid transaction hash format");
                    return s_compose_config_return_response_handler(l_config);
                }
                found = true;
                break;
            }
        }
        json_object_put(l_json_coins);
        if (!found) {
            log_it(L_ERROR, "Specified certificate/pkey hash is not delegated");
            dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_NOT_DELEGATED, "Specified certificate/pkey hash is not delegated");
            return s_compose_config_return_response_handler(l_config);
        }
    }

    if (a_tx_hash_str) {
        const char *l_tx_hash_str_tmp = a_tx_hash_str ? a_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);
        json_object *l_json_answer = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;keys;-net;%s", l_config->net_name);
        if (!l_json_answer) {
            log_it(L_ERROR, "Failed to get rpc answer");
            return s_compose_config_return_response_handler(l_config);
        }
        json_object *l_json_coins = json_object_array_get_idx(l_json_answer, 0);
        if (!l_json_coins) {
            log_it(L_ERROR, "Failed to get keys list");
            return s_compose_config_return_response_handler(l_config);
        }

        bool tx_exists = false;
        int tx_count = json_object_array_length(l_json_coins);
        for (int i = 0; i < tx_count; i++) {
            json_object *tx_item = json_object_array_get_idx(l_json_coins, i);
            const char *tx_hash = json_object_get_string(json_object_object_get(tx_item, "tx_hash"));
            if (tx_hash && strcmp(tx_hash, l_tx_hash_str_tmp) == 0) {
                const char *l_pkey_hash_str = json_object_get_string(json_object_object_get(tx_item, "pkey_hash"));
                log_it(L_ERROR, "Transaction %s has active delegated key %s, need to revoke it first", tx_hash, l_pkey_hash_str);
                json_object_put(l_json_answer);
                dap_json_compose_error_add(l_config->response_handler, DAP_CLI_STAKE_INVALIDATE_KEY_DELEGATED, "Transaction %s has active delegated key %s, need to revoke it first", tx_hash, l_pkey_hash_str);
                return s_compose_config_return_response_handler(l_config);
            }
        }
        json_object_put(l_json_answer);
    }


    dap_chain_datum_tx_t *l_tx = dap_stake_tx_invalidate_compose(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return s_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_stake_tx_invalidate_compose(dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if(!a_config || !a_config->net_name || !*a_config->net_name || !a_tx_hash || !a_wallet_addr || !a_config->url_str || !*a_config->url_str || a_config->port == 0)
        return NULL;

    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    char *l_spent_by_hash = NULL;
    char *l_token_ticker = NULL;
    int l_tx_out_cond_idx = -1;
    dap_chain_datum_tx_t *l_tx = s_get_datum_info_from_rpc(dap_hash_fast_to_str_static(a_tx_hash), a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_tx_out_cond, &l_spent_by_hash, &l_token_ticker, &l_tx_out_cond_idx);
    if (!l_tx_out_cond || l_tx_out_cond_idx == -1) {
        log_it(L_ERROR, "Can't find tx out cond item");
        DAP_DEL_MULTY(l_token_ticker, l_spent_by_hash);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND, "Transaction outputs not found");
        return NULL;
    }
    dap_chain_addr_t l_owner_addr = {};
    dap_chain_addr_fill_from_sign(&l_owner_addr, dap_chain_datum_tx_get_sign(l_tx, 0), l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.net_id);

    if (l_spent_by_hash) {
        log_it(L_ERROR, "Transaction output already spent");
        DAP_DEL_MULTY(l_token_ticker, l_spent_by_hash, l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT, "Transaction outputs not found");
        return NULL;
    }
    
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);

    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, &l_owner_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Transaction outputs not found");
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND, "Transaction outputs not found");
        return NULL;
    }

    int l_out_native_count = json_object_array_length(l_outs_native);
#else
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
    char *l_token_ticker = dap_strdup("mBUZ");
    json_object *l_outs_native = NULL;
    json_object *response = NULL;
    int l_out_native_count = 0;
    int l_tx_out_cond_idx = rand();
    dap_chain_datum_tx_t *l_tx = NULL;
    dap_chain_addr_t l_owner_addr;
    randombytes(&l_owner_addr, sizeof(l_owner_addr));
    dap_chain_tx_out_cond_t *l_tx_out_cond = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_tx_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_tx_out_cond->header.value._lo.b = rand() % 500 + 1;
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
        log_it(L_ERROR, "Not enough funds to pay fees");
        json_object_put(l_outs_native);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fees");
        return NULL;
    }

    // erase and create empty transaction
    dap_chain_datum_tx_delete(l_tx);
    l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_tx_out_cond_idx, 0);

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Error adding input items");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_outs_native);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR, "Error adding input items");
        return NULL;
    }
#endif
    // add 'out_ext' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value, l_token_ticker) == -1) {
        log_it(L_ERROR, "Error adding output items");
        json_object_put(l_outs_native);
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR, "Error adding output items");
        return NULL;
    }
    l_tx_out_cond = NULL;
    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error adding network fee");
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR, "Error adding network fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Error adding fee");
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR, "Error adding fee");
            return NULL;
        }
    }
    // fee coin back
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error adding fee back");
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR, "Error adding fee back");
            return NULL;
        }
    }
    json_object_put(l_outs_native);
    DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
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
                                                    uint256_t* a_value_max, dap_chain_addr_t* a_sovereign_addr, uint256_t* a_sovereign_tax, json_object* response){
    dap_chain_net_srv_order_t* l_order = NULL;
    json_object *orders_array = json_object_array_get_idx(response, 0);
    size_t orders_count = json_object_array_length(orders_array);
    for (size_t i = 0; i < orders_count; i++) {
        json_object *order_obj = json_object_array_get_idx(orders_array, i);
        const char *order_hash_str = json_object_get_string(json_object_object_get(order_obj, "order"));

        if (strcmp(order_hash_str, l_order_hash_str) == 0) {
            l_order = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, sizeof(dap_chain_net_srv_order_t));
            l_order->version = json_object_get_int(json_object_object_get(order_obj, "version"));
            l_order->direction = dap_chain_net_srv_order_direction_from_str(json_object_get_string(json_object_object_get(order_obj, "direction")));
            l_order->ts_created = dap_time_from_str_rfc822(json_object_get_string(json_object_object_get(order_obj, "created")));
            l_order->srv_uid.uint64 = dap_chain_net_srv_uid_from_str(json_object_get_string(json_object_object_get(order_obj, "srv_uid"))).uint64;
            l_order->price = dap_uint256_scan_uninteger(json_object_get_string(json_object_object_get(order_obj, "price_datoshi")));
            strncpy(l_order->price_ticker, json_object_get_string(json_object_object_get(order_obj, "price_token")), DAP_CHAIN_TICKER_SIZE_MAX - 1);
            l_order->price_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
            l_order->units = json_object_get_int(json_object_object_get(order_obj, "units"));
            l_order->price_unit = dap_chain_net_srv_price_unit_uid_from_str(json_object_get_string(json_object_object_get(order_obj, "price_unit")));
            dap_chain_node_addr_from_str(&l_order->node_addr, json_object_get_string(json_object_object_get(order_obj, "node_addr")));
            const char *tx_cond_hash_str = json_object_get_string(json_object_object_get(order_obj, "tx_cond_hash"));
            if (tx_cond_hash_str) {
                dap_chain_hash_fast_from_str(tx_cond_hash_str, &l_order->tx_cond_hash);
            }
            l_order->ext_size = json_object_get_int(json_object_object_get(order_obj, "ext_size"));
            
            if (l_order->ext_size > 0) {
                json_object *external_params = json_object_object_get(order_obj, "external_params");
                if (external_params) {
                    const char *tax_str = json_object_get_string(json_object_object_get(external_params, "tax"));
                    const char *value_max_str = json_object_get_string(json_object_object_get(external_params, "maximum_value"));
                    *a_tax = dap_uint256_scan_decimal(tax_str);
                    *a_value_max = dap_uint256_scan_decimal(value_max_str);
                }
            }

            json_object *conditional_tx_params = json_object_object_get(order_obj, "conditional_tx_params");
            if (conditional_tx_params && json_object_is_type(conditional_tx_params, json_type_object)) {
                const char *sovereign_tax_str = json_object_get_string(json_object_object_get(conditional_tx_params, "sovereign_tax"));
                const char *sovereign_addr_str = json_object_get_string(json_object_object_get(conditional_tx_params, "sovereign_addr"));
                *a_sovereign_tax = dap_uint256_scan_decimal(sovereign_tax_str);
                if (sovereign_addr_str) {
                    a_sovereign_addr = dap_chain_addr_from_str(sovereign_addr_str);
                    if (!a_sovereign_addr) {
                        log_it(L_ERROR, "Invalid sovereign address format");
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

    json_object *response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "order;list;staker;-net;%s", 
                                                                  a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "Failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return NULL;
    }

    dap_chain_net_srv_order_t *l_order = dap_check_remote_srv_order(a_config->net_name, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
    json_object_put(response);

    if (!l_order) {
        response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "order;list;validator;-net;%s", 
                                                          a_config->net_name);
        if (!response) {
            log_it(L_ERROR, "Failed to get response from remote node");
            dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_RPC_RESPONSE, "Error: Failed to get response from remote node");
            return NULL;
        }
        l_order = dap_check_remote_srv_order(a_config->net_name, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
        json_object_put(response);
    }
    return l_order;
}

typedef enum {
    DAP_GET_REMOTE_SRV_ORDER_SIGN_RPC_RESPONSE = -1,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_FIRST_ELEMENT = -2,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN = -3
} dap_get_remote_srv_order_sign_error_t;

dap_sign_t* dap_get_remote_srv_order_sign(const char* l_order_hash_str, compose_config_t *a_config){

    json_object *response = dap_request_command_to_rpc_with_params(a_config, "net_srv", "order;dump;-hash;%s;-need_sign;-net;%s", 
                                                                  l_order_hash_str, a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "Failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return NULL;
    }
    json_object *l_response_array = json_object_array_get_idx(response, 0);
    if (!l_response_array) {
        log_it(L_ERROR, "Can't get the first element from the response array");
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_FIRST_ELEMENT, "Error: Can't get the first element from the response array");
        json_object_put(response);
        return NULL;
    }

    const char *l_sign_b64_str = json_object_get_string(json_object_object_get(l_response_array, "sig_b64"));
    if (!l_sign_b64_str) {
        log_it(L_ERROR, "Can't get base64-encoded sign from SIG item");
        dap_json_compose_error_add(a_config->response_handler, DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN, "Error: Can't get base64-encoded sign from SIG item");
        json_object_put(response);
        return NULL;
    }

    // *a_sign_size = json_object_get_int(json_object_object_get(l_response_array, "sig_b64_size"));
    int64_t l_sign_b64_strlen = json_object_get_string_len(json_object_object_get(l_response_array, "sig_b64"));
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
    json_object_put(response);
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
json_object* dap_cli_srv_stake_delegate_compose(const char* a_net_str, dap_chain_addr_t *a_wallet_addr, const char* a_cert_str, 
                                        const char* a_pkey_full_str, const char* a_value_str, const char* a_node_addr_str, 
                                        const char* a_order_hash_str, const char* a_url_str, uint16_t a_port, const char* a_cert_path, const char* a_sovereign_addr_str, const char* a_fee_str) {
    compose_config_t *l_config = s_compose_config_init(a_net_str, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        json_object* l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE, "Can't create compose config");
        return l_json_obj_ret;
    }
    dap_chain_addr_t l_signing_addr = {}, l_sovereign_addr = {};
    uint256_t l_sovereign_tax = uint256_0;
    uint256_t l_value = uint256_0;
    if (a_value_str) {
        l_value = dap_chain_balance_scan(a_value_str);
        if (IS_ZERO_256(l_value)) {
            log_it(L_ERROR, "Unrecognized number in '-value' param");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-value' param");
            return s_compose_config_return_response_handler(l_config);
        }
    }
    dap_pkey_t *l_pkey = NULL;
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    if (a_cert_str) {
        dap_cert_t *l_signing_cert = dap_cert_find_by_name(a_cert_str);
        if (!l_signing_cert) {
            log_it(L_ERROR, "Specified certificate not found");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND, "Specified certificate not found");
            return s_compose_config_return_response_handler(l_config);
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, dap_get_net_id(a_net_str))) {
            log_it(L_ERROR, "Specified certificate is wrong");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG, "Specified certificate is wrong");
            return s_compose_config_return_response_handler(l_config);
        }
        l_pkey = dap_pkey_from_enc_key(l_signing_cert->enc_key);
    }  else if (a_pkey_full_str) {
        l_pkey = dap_pkey_get_from_str(a_pkey_full_str);
        if (!l_pkey) {
            log_it(L_ERROR, "Invalid pkey string format");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey string format, can't get pkey_full");
            return s_compose_config_return_response_handler(l_config);
        }
        dap_chain_hash_fast_t l_hash_public_key = {0};
        if (!dap_pkey_get_hash(l_pkey, &l_hash_public_key)) {
            log_it(L_ERROR, "Invalid pkey hash format");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey hash format");
            return s_compose_config_return_response_handler(l_config);
        }
        dap_chain_addr_fill(&l_signing_addr, dap_pkey_type_to_sign_type((l_pkey->header).type), &l_hash_public_key, dap_get_net_id(a_net_str));
    }

    dap_chain_node_addr_t l_node_addr = g_node_addr;
    if (a_node_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_addr, a_node_addr_str)) {
            log_it(L_ERROR, "Unrecognized node addr %s", a_node_addr_str);
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR, "Unrecognized node addr %s", a_node_addr_str);
            return s_compose_config_return_response_handler(l_config);
        }
    }
    if (a_order_hash_str) {
        uint256_t l_tax;
        uint256_t l_value_max;
        int l_prev_tx_count = 0;
        dap_chain_net_srv_order_t* l_order = dap_get_remote_srv_order(a_order_hash_str, &l_tax, &l_value_max, &l_sovereign_addr, &l_sovereign_tax, l_config);
        if (!l_order) {
            log_it(L_ERROR, "Failed to get order from remote node");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND, "Error: Failed to get order from remote node");
            return s_compose_config_return_response_handler(l_config);
        }
        l_sovereign_tax = l_tax;

        if (l_order->direction == SERV_DIR_BUY) { // Staker order
            char *l_token_ticker = NULL;
            if (!a_cert_str) {
                log_it(L_ERROR, "Command 'delegate' requires parameter -cert with this order type");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED, "Command 'delegate' requires parameter -cert with this order type");
                return s_compose_config_return_response_handler(l_config);
            }
            if (l_order->ext_size != 0) {
                log_it(L_ERROR, "Specified order has invalid size");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE, "Specified order has invalid size");
                DAP_DELETE(l_order);
                return s_compose_config_return_response_handler(l_config);
            }

            dap_chain_tx_out_cond_t *l_cond_tx = NULL;
            dap_chain_datum_tx_t *l_datum = s_get_datum_info_from_rpc(dap_chain_hash_fast_to_str_static(&l_order->tx_cond_hash), l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_cond_tx, NULL, &l_token_ticker, NULL);
            dap_chain_datum_tx_delete(l_datum);
            if (!l_cond_tx) {
                log_it(L_ERROR, "Failed to get cond tx info from RPC");
                DAP_DELETE(l_cond_tx);
                return s_compose_config_return_response_handler(l_config);
            }

            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, s_get_native_ticker(a_net_str));

            if (dap_strcmp(l_token_ticker, l_delegated_ticker)) {
                log_it(L_ERROR, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                return s_compose_config_return_response_handler(l_config);
            }
            if (l_cond_tx->tsd_size != dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size(true, 0)) {
                log_it(L_ERROR, "The order's conditional transaction has invalid format");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT, "The order's conditional transaction has invalid format");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return s_compose_config_return_response_handler(l_config);
            }
            if (compare256(l_cond_tx->header.value, l_order->price)) {
                log_it(L_ERROR, "The order's conditional transaction has different value");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE, "The order's conditional transaction has different value");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return s_compose_config_return_response_handler(l_config);
            }
            if (!dap_chain_addr_is_blank(&l_cond_tx->subtype.srv_stake_pos_delegate.signing_addr) ||
                    l_cond_tx->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
                log_it(L_ERROR, "The order's conditional transaction gas not blank address or key");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR, "The order's conditional transaction gas not blank address or key");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return s_compose_config_return_response_handler(l_config);
            }
            l_value = l_order->price;
            DAP_DELETE(l_cond_tx);
        } else {
            if (!a_value_str) {
                log_it(L_ERROR, "Command 'delegate' requires parameter -value with this order type");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED, "Command 'delegate' requires parameter -value with this order type");
                return s_compose_config_return_response_handler(l_config);
            }
            if (a_sovereign_addr_str) {
                dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(a_sovereign_addr_str);
                if (!l_spec_addr) {
                    log_it(L_ERROR, "Specified address is invalid");
                    dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR, "Specified address is invalid");
                    return s_compose_config_return_response_handler(l_config);
                }
                l_sovereign_addr = *l_spec_addr;
                DAP_DELETE(l_spec_addr);
            } else
                l_sovereign_addr = *a_wallet_addr;

            if (a_order_hash_str && compare256(l_value, l_order->price) == -1) {
                const char *l_coin_min_str, *l_value_min_str =
                    dap_uint256_to_char(l_order->price, &l_coin_min_str);
                log_it(L_ERROR, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
                return s_compose_config_return_response_handler(l_config);
            }
            if (a_order_hash_str && compare256(l_value, l_value_max) == 1) {
                const char *l_coin_max_str, *l_value_max_str =
                    dap_uint256_to_char(l_value_max, &l_coin_max_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH, "Number in '-value' param %s is higher than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_max_str, l_value_max_str);
                return s_compose_config_return_response_handler(l_config);
            }
            size_t l_sign_size = 0;
            dap_sign_t *l_sign = dap_get_remote_srv_order_sign(a_order_hash_str, l_config);
            if (!l_sign) {
                log_it(L_ERROR, "Specified order is unsigned");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER, "Specified order is unsigned");
                DAP_DELETE(l_order);
                return s_compose_config_return_response_handler(l_config);
            }
            dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, dap_get_net_id(a_net_str));
            l_pkey = dap_pkey_get_from_sign(l_sign);
            DAP_DELETE(l_sign);
            char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, s_get_native_ticker(a_net_str));
            if (dap_strcmp(l_order->price_ticker, l_delegated_ticker_str)) {
                log_it(L_ERROR, "Specified order is invalid");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER, "Specified order is invalid");
                DAP_DELETE(l_order);
                return s_compose_config_return_response_handler(l_config);
            }
            l_node_addr = l_order->node_addr;
        }
        DAP_DELETE(l_order);
        if (compare256(l_sovereign_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
                compare256(l_sovereign_tax, GET_256_FROM_64(100)) == -1) {
            log_it(L_ERROR, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            return s_compose_config_return_response_handler(l_config);
        }
        DIV_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
    }
    if (!l_pkey) {
        log_it(L_ERROR, "Pkey not defined");
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED, "Pkey not defined");
        return s_compose_config_return_response_handler(l_config);
    }

    if (!l_node_addr.uint64) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR, "Invalid node addr, is sero");
        return s_compose_config_return_response_handler(l_config);
    }

    // int l_check_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
    // if (l_check_result) {
    //     dap_json_compose_error_add(l_config->response_handler, l_check_result, "Key and node verification error");
    //     return s_compose_config_return_response_handler(l_config);
    // }
 

    uint256_t l_allowed_min = s_get_key_delegating_min_value(l_config);
    if (compare256(l_value, l_allowed_min) == -1) {
        const char *l_coin_min_str, *l_value_min_str = dap_uint256_to_char(l_allowed_min, &l_coin_min_str);
        log_it(L_ERROR, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                          a_value_str, l_coin_min_str, l_value_min_str);
        return s_compose_config_return_response_handler(l_config);
    }

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "Unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-fee' param");
        return s_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_t *l_tx = dap_stake_tx_create_compose(a_wallet_addr, l_value, l_fee, &l_signing_addr, &l_node_addr,
                                                   a_order_hash_str ? &l_sovereign_addr : NULL, l_sovereign_tax, l_prev_tx, l_pkey, l_config);
    
    DAP_DELETE(l_pkey);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return s_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_stake_tx_create_compose(dap_chain_addr_t *a_wallet_addr,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, compose_config_t *a_config)
{
    if  (!a_wallet_addr || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr) {
        log_it(L_ERROR, "Invalid parameters for transaction creation");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters for transaction creation");
        return NULL;
    }
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
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
    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Failed to get remote tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE, "Not enough funds to pay fee");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    json_object *l_outs_delegated = dap_get_remote_tx_outs(l_delegated_ticker, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        log_it(L_ERROR, "Failed to get remote tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_delegated_count = json_object_array_length(l_outs_delegated); 
#else
    json_object *l_outs_native = NULL;
    json_object *l_outs_delegated = NULL;
    int l_out_native_count = 0;
    int l_out_delegated_count = 0;
#endif

    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                    l_fee_total, 
                                                    &l_fee_transfer);
    if (!l_list_fee_out) {
        log_it(L_ERROR, "Failed to get list tx outs from json");
        json_object_put(l_outs_native);
        json_object_put(l_outs_delegated);
        DAP_DEL_Z(l_net_fee_addr);
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
            log_it(L_ERROR, "Failed to get list tx outs from json");
            json_object_put(l_outs_native);
            json_object_put(l_outs_delegated);
            DAP_DEL_Z(l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
            return NULL;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            log_it(L_ERROR, "Failed to add in item");
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
            log_it(L_ERROR, "Failed to add in cond item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
            goto tx_fail;
        }
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Failed to add in item");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
        goto tx_fail;
    }
#endif
    // add 'out_cond' & 'out_ext' items
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr,
                                                                                          a_sovereign_addr, a_sovereign_tax, a_pkey);

    if (!l_tx_out) {
        log_it(L_ERROR, "Failed to create cond tx out");
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
                log_it(L_ERROR, "Failed to add out ext item");
                dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR, "Error creating transaction output");
                goto tx_fail;
            }
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error with network fee, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR, "Error with network fee, failed to add item");
            goto tx_fail;
        }
    }
    DAP_DEL_Z(l_net_fee_addr);
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Error with validator fee, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR, "Error with validator fee, failed to add item");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error with fee back, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR, "Error with fee back, failed to add item");
            goto tx_fail;
        }
    }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    DAP_DEL_Z(l_net_fee_addr);
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
json_object* dap_cli_srv_stake_order_create_staker_compose(const char *l_net_str, const char *l_value_str, const char *l_fee_str, 
                                                          const char *l_tax_str, const char *l_addr_str, dap_chain_addr_t *a_wallet_addr, 
                                                          const char *l_url_str, uint16_t l_port, const char *l_cert_path) {
    compose_config_t *l_config = s_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        json_object *l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "Unrecognized number in '-value' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE, "Format -value <256 bit integer>");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "Unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_tax = dap_chain_balance_coins_scan(l_tax_str);
    if (compare256(l_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
            compare256(l_tax, GET_256_FROM_64(100)) == -1) {
        log_it(L_ERROR, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_addr_t l_addr = {};
    if (l_addr_str) {
        dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_addr_str);
        if (!l_spec_addr) {
            log_it(L_ERROR, "Specified address is invalid");
            dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR, "Specified address is invalid");
            return s_compose_config_return_response_handler(l_config);
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
    } else {
        log_it(L_ERROR, "Address not defined");  
    }

    return s_compose_config_return_response_handler(l_config);
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
json_object * dap_cli_xchange_order_remove_compose(const char *l_net_str, const char *l_order_hash_str, const char *l_fee_str, dap_chain_addr_t *a_wallet_addr, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {

    compose_config_t *l_config = s_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        json_object *l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "Unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return s_compose_config_return_response_handler(l_config);
    }
    dap_hash_fast_t l_tx_hash = {};
    dap_chain_hash_fast_from_str(l_order_hash_str, &l_tx_hash);
    if (dap_hash_fast_is_blank(&l_tx_hash)) {
        log_it(L_ERROR, "Invalid order hash");
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH, "Invalid order hash");
        return s_compose_config_return_response_handler(l_config);
    }
    char *l_tx_hash_ret = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_order_remove_compose(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    
    return s_compose_config_return_response_handler(l_config);
}

static bool s_process_ledger_response(dap_chain_tx_out_cond_subtype_t a_cond_type, 
                                                dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_out_hash, compose_config_t *a_config) {
    *a_out_hash = *a_tx_hash;
    int l_prev_tx_count = 0;
    dap_chain_hash_fast_t l_hash = {};
    
    json_object *response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                  dap_chain_hash_fast_to_str_static(a_tx_hash), a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "Failed to get response from remote node");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return false;
    }
    
    json_object *l_response_array = json_object_array_get_idx(response, 0);
    if (!l_response_array) {
        log_it(L_ERROR, "Can't get the first element from the response array");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Can't get the first element from the response array");
        json_object_put(response);
        return false;
    }

    json_object *items = json_object_object_get(l_response_array, "items");
    if (!items) {
        log_it(L_ERROR, "No items found in response");
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: No items found in response");
        return false;
    }
    bool l_found = false;
    int items_count = json_object_array_length(items);
    for (int i = 0; i < items_count; i++) {
        json_object *item = json_object_array_get_idx(items, i);
        const char *item_type = json_object_get_string(json_object_object_get(item, "type"));
        if (dap_strcmp(item_type, "out_cond") == 0) {
            const char *subtype = json_object_get_string(json_object_object_get(item, "subtype"));
            if (!dap_strcmp(subtype, dap_chain_tx_out_cond_subtype_to_str(a_cond_type))) {
                dap_chain_hash_fast_from_str(json_object_get_string(json_object_object_get(item, "hash")), &l_hash);
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
    json_object *spent_outs = json_object_object_get(l_response_array, "spent_OUTs");
    if (spent_outs) {
        int spent_outs_count = json_object_array_length(spent_outs);
        for (int i = 0; i < spent_outs_count; i++) {
            json_object *spent_out = json_object_array_get_idx(spent_outs, i);
            int out_index = json_object_get_int(json_object_object_get(spent_out, "OUT - "));
            if (out_index == l_prev_tx_count) {
                dap_chain_hash_fast_from_str(json_object_get_string(json_object_object_get(spent_out, "is_spent_by_tx")), &l_hash);
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

dap_chain_hash_fast_t dap_ledger_get_final_chain_tx_hash_compose(dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only, compose_config_t *a_config)
{
    dap_chain_hash_fast_t l_hash = { };
    dap_return_val_if_pass(!a_tx_hash || dap_hash_fast_is_blank(a_tx_hash), l_hash);
    l_hash = *a_tx_hash;

    while(s_process_ledger_response( a_cond_type, a_tx_hash, &l_hash, a_config));

    return l_hash;
}

dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_price_from_order_compose(dap_chain_tx_out_cond_t *a_cond_tx, 
                                                                                    dap_time_t a_ts_created, dap_hash_fast_t *a_order_hash, dap_hash_fast_t *a_hash_out, const char *a_token_ticker,
                                                                                    uint256_t *a_fee, bool a_ret_is_invalid, compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_cond_tx || !a_order_hash || !a_config, NULL);
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_srv_xchange_price_t, NULL);
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
            log_it(L_ERROR, "This order have no active conditional transaction");
            dap_hash_fast_t l_tx_hash_zero = {0};
            l_price->tx_hash = l_tx_hash_zero;
            return l_price;
        }
    }

    return NULL;
}

dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, uint32_t a_prev_cond_idx, compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config || !a_price || !a_wallet_addr, NULL);

    if (!a_price) {
        log_it(L_ERROR, "A_price is NULL");
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_price NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    if (!a_wallet_addr) {
        log_it(L_ERROR, "A_wallet_addr is NULL");
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_wallet_addr NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST

    bool l_single_channel = !dap_strcmp(a_tx_ticker, l_native_ticker);

    if (!dap_chain_addr_compare(a_seller_addr, a_wallet_addr)) {
        log_it(L_ERROR, "Not owner");
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
        json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_seller_addr, a_config);
        if (!l_outs_native) {
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        int l_out_native_count = json_object_array_length(l_outs_native);
        uint256_t l_transfer_fee = {}, l_fee_back = {};
        // list of transaction with 'out' items to get net fee
        dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_transfer_fee);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "Not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Not enough funds to pay fee");
            json_object_put(l_outs_native);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }


        // add 'in' items to net fee
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED, "Can't compose the transaction input");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, a_cond_tx->header.value, a_tx_ticker) == -1) {
            log_it(L_ERROR, "Can't add returning coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        // put fee coinback
        SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_back, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add fee cachback output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED, "Cant add fee cachback output");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }

            // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                DAP_DEL_Z(l_addr_fee);
                return NULL;
            }
        }


    } else {
        uint256_t l_coin_back = {};
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (compare256(l_total_fee, a_cond_tx->header.value) >= 0) {
            log_it(L_ERROR, "Total fee is greater or equal than order liquidity");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH, "Total fee is greater or equal than order liquidity");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
#endif
        SUBTRACT_256_256(a_cond_tx->header.value, l_total_fee, &l_coin_back);
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_coin_back, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add returning coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        DAP_DEL_Z(l_addr_fee);

        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                log_it(L_ERROR, "Can't add validator's fee output");
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
    dap_return_val_if_pass(!a_hash_tx || !a_wallet_addr || !a_config, NULL);
    if(IS_ZERO_256(a_fee)){
        log_it(L_ERROR, "Fee must be greater than 0");
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return NULL;
    }

    dap_time_t ts_created = 0;

    dap_chain_addr_t l_seller_addr = {};
    char *token_ticker = NULL;
    uint32_t l_prev_cond_idx = 0;
    dap_hash_fast_t l_hash_out = {};
    dap_chain_tx_out_cond_t* l_cond_tx_last = dap_find_last_xchange_tx(a_hash_tx, &l_seller_addr, a_config, NULL, &token_ticker, &l_prev_cond_idx, &l_hash_out);

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx_last, ts_created, a_hash_tx, &l_hash_out, token_ticker, &a_fee, false, a_config);
    if (!l_price) {
        log_it(L_ERROR, "Failed to get price");
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
json_object *dap_tx_create_xchange_purchase_compose (const char *a_net_name, const char *a_order_hash, const char* a_value,
                                                     const char* a_fee, dap_chain_addr_t *a_wallet_addr, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    // Input validation
    if (!a_net_name || !a_order_hash || !a_value || !a_fee || !a_wallet_addr || !a_url_str) {
        log_it(L_ERROR, "Invalid input parameters");
        json_object *l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid input parameters");
        return l_json_obj_ret;
    }

    compose_config_t *l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        json_object *l_json_obj_ret = json_object_new_object();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_datoshi_buy = dap_chain_balance_scan(a_value);
    if (IS_ZERO_256(l_datoshi_buy)) {
        log_it(L_ERROR, "Value must be greater than 0");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Value must be greater than 0");
        return s_compose_config_return_response_handler(l_config);
    }

    uint256_t l_datoshi_fee = dap_chain_balance_scan(a_fee);
    if (IS_ZERO_256(l_datoshi_fee)) {
        log_it(L_ERROR, "Fee must be greater than 0");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_hash = {};
    if (dap_chain_hash_fast_from_str(a_order_hash, &l_tx_hash) != 0 || dap_hash_fast_is_blank(&l_tx_hash)) {
        log_it(L_ERROR, "Invalid order hash");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, "Invalid order hash");
        return s_compose_config_return_response_handler(l_config);
    }

    char *l_str_ret_hash = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_purchase_compose(&l_tx_hash, l_datoshi_buy, l_datoshi_fee,
                                                        a_wallet_addr, &l_str_ret_hash, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        DAP_DELETE(l_str_ret_hash); // Free allocated hash string
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return s_compose_config_return_response_handler(l_config);
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
dap_chain_tx_out_cond_t *dap_find_last_xchange_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  compose_config_t * a_config, 
                                                  dap_time_t *a_ts_created, char **a_token_ticker, uint32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out) {
    dap_chain_tx_out_cond_t *l_cond_tx = NULL;
    dap_chain_tx_out_cond_t *l_ret = NULL;
    dap_hash_fast_t l_current_hash = {};
    dap_chain_datum_tx_t *l_tx = NULL;

    char *l_spent_by_hash = dap_chain_hash_fast_to_str_new(a_order_hash);
    while (l_spent_by_hash) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_cond_tx);
        if (dap_chain_hash_fast_from_str(l_spent_by_hash, &l_current_hash)) {
            log_it(L_ERROR, "Failed to get hash from string");
            dap_json_compose_error_add(a_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, 
                                     "Failed to get hash from string");
            return NULL;
        }
        l_tx = s_get_datum_info_from_rpc(l_spent_by_hash, a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_cond_tx, &l_spent_by_hash, a_token_ticker, (int *)a_prev_cond_idx);

        if (!l_tx) {
            log_it(L_ERROR, "Failed to get datum info from remote node");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE, 
                                     "Failed to get datum info from remote node");
            return NULL;
        }
    }
    
    if (!l_cond_tx) {
        log_it(L_ERROR, "No transaction output condition found");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "No transaction output condition found");
        return NULL;
    }
    l_ret = l_cond_tx;
    *a_seller_addr = l_cond_tx->subtype.srv_xchange.seller_addr;

    if (a_ts_created) {
        *a_ts_created = l_tx->header.ts_created;
    }
    *a_hash_out = l_current_hash;
    dap_chain_datum_tx_delete(l_tx);
    return l_ret;
}

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, char **a_hash_out, compose_config_t *a_config){
    dap_return_val_if_pass(!a_config || !a_order_hash || !a_wallet_addr || !a_hash_out, NULL);

    char *l_token_ticker = NULL;
    uint32_t l_prev_cond_idx = 0;
    dap_chain_addr_t l_seller_addr = {0};
    dap_hash_fast_t l_hash_out = {0};
    dap_time_t l_ts_created = 0;
    dap_chain_tx_out_cond_t *l_cond_tx = dap_find_last_xchange_tx(a_order_hash, &l_seller_addr, a_config, &l_ts_created, &l_token_ticker, &l_prev_cond_idx, &l_hash_out);
    if (!l_cond_tx) {
        log_it(L_ERROR, "Failed to find last xchange transaction");
        return NULL;
    }

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx, l_ts_created, a_order_hash, &l_hash_out, l_token_ticker, &a_fee, false, a_config);
    if(!l_price){
        log_it(L_ERROR, "Failed to create price from order");
        DAP_DELETE(l_cond_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE, "Failed to create price from order");
        return NULL;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_exchange_compose(l_price, a_wallet_addr, a_value, a_fee, l_cond_tx, l_prev_cond_idx, a_config);
    DAP_DEL_MULTY(l_cond_tx, l_price);
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create exchange transaction");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Failed to create exchange transaction");
        return NULL;
    }
    return l_tx;
}


dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                          uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, uint32_t a_prev_cond_idx, compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_buyer_addr || !a_cond_tx || !a_config, NULL);

    const char *l_native_ticker = s_get_native_ticker(a_config->net_name);
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

    json_object *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_buyer_addr, a_price->token_buy, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "Not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }
#endif

    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        json_object_put(l_outs);
        DAP_DEL_Z(l_net_fee_addr);
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
                log_it(L_ERROR, "Not enough funds to pay fee");
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
                json_object_put(l_outs);
                dap_list_free_full(l_list_used_out, NULL);
                DAP_DEL_Z(l_net_fee_addr);
                return NULL;
            }
        }
    }

    json_object_put(l_outs);

    // Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Can't create transaction");
        dap_list_free_full(l_list_used_out, NULL);
        dap_list_free_full(l_list_fee_out, NULL);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_TX_CREATE_ERROR, "Can't create transaction");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_list_free_full(l_list_fee_out, NULL);
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Can't compose the transaction input");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }
#endif

    if (!l_pay_with_native && !l_buy_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't compose the transaction input");
            DAP_DEL_Z(l_net_fee_addr);
            return NULL;
        }
#endif
    }

    const dap_chain_addr_t *l_seller_addr = &a_cond_tx->subtype.srv_xchange.seller_addr;
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0)) {
        log_it(L_ERROR, "Can't add conditional input");
        dap_chain_datum_tx_delete(l_tx);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add conditional input");
        DAP_DEL_Z(l_net_fee_addr);
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
                log_it(L_ERROR, "Fee is greater or equal than transfer value");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Fee is greater or equal than transfer value");
                DAP_DEL_Z(l_net_fee_addr);
                return NULL;
            }
#endif
            SUBTRACT_256_256(l_datoshi_sell, l_total_fee, &l_value_sell);
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_sell, a_price->token_sell) == -1) {
            log_it(L_ERROR, "Can't add selling coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add selling coins output");
            DAP_DEL_Z(l_net_fee_addr);
            return NULL;
        }
    } else {
        log_it(L_ERROR, "Price rate is 0");
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_RATE_ERROR, "Can't add selling coins output because price rate is 0");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }
    
    if (compare256(a_cond_tx->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(a_cond_tx->header.value, l_datoshi_sell, &l_value_back);
        
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, dap_get_net_id(a_config->net_name), l_value_back,
                    dap_get_net_id(a_config->net_name), a_price->token_buy, a_price->rate,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            log_it(L_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            dap_chain_datum_tx_delete(l_tx);
            // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            DAP_DEL_Z(l_net_fee_addr);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } 

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        log_it(L_ERROR, "Can't add buying coins output");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins output");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }
    
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            log_it(L_ERROR, "Can't add validator fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator fee output");
            DAP_DEL_Z(l_net_fee_addr);
            return NULL;
        }
    }

    // Add network fee
    if (l_net_fee_used && !IS_ZERO_256(l_net_fee)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add net fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add net fee output");
            DAP_DEL_Z(l_net_fee_addr);
            return NULL;
        }
    }
    DAP_DEL_Z(l_net_fee_addr);

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            log_it(L_ERROR, "Can't add buying coins back output");
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
                log_it(L_ERROR, "Can't add buying coins back output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
    }

    return l_tx;
}
