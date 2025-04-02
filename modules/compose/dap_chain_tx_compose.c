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

#include <netdb.h>
#include <json-c/json.h>



const char *arg_wallets_path = NULL;

static const char* s_get_native_ticker(const char* name) {
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].native_ticker;
        }
    }
    return NULL;
}

static dap_chain_net_id_t s_get_net_id(const char* name) {
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].net_id;
        }
    }
    dap_chain_net_id_t empty_id = {.uint64 = 0};
    return empty_id;
}

static const char* s_get_net_url(const char* name) {
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].url;
        }
    }
    return NULL;
}

static uint16_t s_get_net_port(const char* name) {
    for (int i = 0; i < NET_COUNT; i++) {
        if (strcmp(netinfo[i].name, name) == 0) {
            return netinfo[i].port;
        }
    }
    return 0;
}


int dap_tx_json_tsd_add(json_object * json_tx, json_object * json_add) {
    json_object *items_array;
    if (!json_object_object_get_ex(json_tx, "items", &items_array)) {
        fprintf(stderr, "Failed to get 'items' array\n");
        return 1;
    }
    json_object_array_add(items_array, json_add);
    return 0;
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
                                            http_status_code_t http_status_code) {
    (void)http_status_code;
    struct cmd_request *l_cmd_request = (struct cmd_request *)a_arg;
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
#ifdef DAP_OS_WINDOWS
    EnterCriticalSection(&l_cmd_request->wait_crit_sec);
    l_cmd_request->response = NULL;
    l_cmd_request->error_code = a_error_code;
    WakeConditionVariable(&l_cmd_request->wait_cond);
    LeaveCriticalSection(&l_cmd_request->wait_crit_sec);
#else
    pthread_mutex_lock(&l_cmd_request->wait_mutex);
    l_cmd_request->response = NULL;
    l_cmd_request->error_code = a_error_code;
    pthread_cond_signal(&l_cmd_request->wait_cond);
    pthread_mutex_unlock(&l_cmd_request->wait_mutex);
#endif
}


static int dap_chain_cmd_list_wait(struct cmd_request *a_cmd_request, int a_timeout_ms) {
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
    clock_gettime(CLOCK_MONOTONIC, &l_cond_timeout);
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
    int ret = 0;

    if (a_cmd_request->error_code) {
        ret = - 1;
    } else if (a_cmd_request->response) {
            *a_response_out = json_tokener_parse(a_cmd_request->response);
            *a_response_out_size = a_cmd_request->response_size;
    } else {
        ret = -2;
    }

    return ret;
}

static json_object* s_request_command_to_rpc(const char *request, const char * a_net_name, const char * a_url_str, uint16_t a_port) {
    json_object * l_response = NULL;
    size_t l_response_size = 0; // Initialize to avoid potential undefined behavior
    struct cmd_request* l_cmd_request = s_cmd_request_init();

    if (!l_cmd_request) {
        printf("Error: Failed to initialize command request\n");
        return NULL;
    }

    dap_client_http_request(dap_worker_get_auto(),
                                a_url_str ? a_url_str : s_get_net_url(a_net_name),
                                a_port ? a_port : s_get_net_port(a_net_name),
                                "POST", "application/json",
                                NULL, request, strlen(request), NULL,
                                s_cmd_response_handler, s_cmd_error_handler,
                                l_cmd_request, NULL);

    int l_ret = dap_chain_cmd_list_wait(l_cmd_request, 15000);

    if (!l_ret){
        if (s_cmd_request_get_response(l_cmd_request, &l_response, &l_response_size)) {
            printf( "Response error code: %d", l_cmd_request->error_code);
        }
    } else {
        printf("Error: Command list wait failed with code %d\n", l_ret);
    }

    s_cmd_request_free(l_cmd_request);
    return l_response;
}

static json_object* s_request_command_parse(json_object *l_response) {
    if (!l_response) {
        printf("Error: Response is NULL\n");
        return NULL;
    }

    json_object * l_result = NULL;
    if (!json_object_object_get_ex(l_response, "result", &l_result)) {
        printf("Error: Failed to get 'result' from response\n");
        return NULL;
    }

    json_object *errors_array = NULL;
    if (json_object_is_type(l_result, json_type_array) && json_object_array_length(l_result) > 0) {
        json_object *first_element = json_object_array_get_idx(l_result, 0);
        if (json_object_object_get_ex(first_element, "errors", &errors_array)) {
            int errors_len = json_object_array_length(errors_array);
            for (int j = 0; j < errors_len; j++) {
                json_object *error_obj = json_object_array_get_idx(errors_array, j);
                json_object *error_code = NULL, *error_message = NULL;
                if (json_object_object_get_ex(error_obj, "code", &error_code) &&
                    json_object_object_get_ex(error_obj, "message", &error_message)) {
                    printf("Error %d: %s\n", json_object_get_int(error_code), json_object_get_string(error_message));
                }
            }
            l_result = NULL;
        }
    }
    json_object_get(l_result);
    return l_result;
}

json_object* dap_request_command_to_rpc(const char *request, const char * a_net_name, const char * a_url_str, uint16_t a_port) {
    json_object * l_response = s_request_command_to_rpc(request, a_net_name, a_url_str, a_port);
    if (!l_response) {
        printf("Error: Failed to get response from RPC request\n");
        return NULL;
    }

    json_object * l_result = s_request_command_parse(l_response);
    json_object_put(l_response);
    return l_result;
}


bool dap_get_remote_net_fee_and_address(const char *l_net_name, uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee, const char * a_url_str, uint16_t a_port) {
    char data[512];
    snprintf(data, sizeof(data), "{\"method\": \"net\",\"params\": [\"net;get;fee;-net;%s\"],\"id\": \"1\"}", l_net_name);
    json_object *l_json_get_fee = dap_request_command_to_rpc(data, l_net_name, a_url_str, a_port);
    if (!l_json_get_fee) {
        return false;
    }

    json_object *l_first_result = json_object_array_get_idx(l_json_get_fee, 0);
    if (!l_first_result || !json_object_is_type(l_first_result, json_type_object)) {
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_fees = NULL;
    if (!json_object_object_get_ex(l_first_result, "fees", &l_fees) || 
        !json_object_is_type(l_fees, json_type_object)) {
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_network = NULL;
    if (!json_object_object_get_ex(l_fees, "network", &l_network) || 
        !json_object_is_type(l_network, json_type_object)) {
        json_object_put(l_json_get_fee);
        return false;
    }

    json_object *l_balance = NULL;
    if (!json_object_object_get_ex(l_network, "balance", &l_balance) || 
        !json_object_is_type(l_balance, json_type_string)) {
        json_object_put(l_json_get_fee);
        return false;
    }
    *a_net_fee = dap_chain_balance_scan(json_object_get_string(l_balance));

    json_object *l_addr = NULL;
    if (!json_object_object_get_ex(l_network, "addr", &l_addr) || 
        !json_object_is_type(l_addr, json_type_string)) {
        json_object_put(l_json_get_fee);
        return false;
    }
    *l_addr_fee = dap_chain_addr_from_str(json_object_get_string(l_addr));

    json_object_put(l_json_get_fee);
    return true;
}

bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker, const char *l_net_name,
                                         json_object **l_outs, int *l_outputs_count, const char * a_url_str, uint16_t a_port) {
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"wallet\",\"params\": [\"wallet;outputs;-addr;%s;-token;%s;-net;%s\"],\"id\": \"1\"}", 
            dap_chain_addr_to_str(a_addr_from), a_token_ticker, l_net_name);
    json_object *l_json_outs = dap_request_command_to_rpc(data, l_net_name, a_url_str, a_port);
    if (!l_json_outs) {
        return false;
    }

    if (!json_object_is_type(l_json_outs, json_type_array)) {
        json_object_put(l_json_outs);
        return false;
    }

    if (json_object_array_length(l_json_outs) == 0) {
        json_object_put(l_json_outs);
        return false;
    }

    json_object *l_first_array = json_object_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !json_object_is_type(l_first_array, json_type_array)) {
        json_object_put(l_json_outs);
        return false;
    }

    json_object *l_first_item = json_object_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        json_object_put(l_json_outs);
        return false;
    }

    if (!json_object_object_get_ex(l_first_item, "outs", l_outs) ||
        !json_object_is_type(*l_outs, json_type_array)) {
        json_object_put(l_json_outs);
        return false;
    }

    *l_outputs_count = json_object_array_length(*l_outs);
    json_object_get(*l_outs);
    json_object_put(l_json_outs);
    return true;
}


int dap_tx_create_xchange_compose(int argc, char ** argv) {
    int arg_index = 1;
    const char *l_net_name = NULL;
    const char *l_token_sell = NULL;
    const char *l_token_buy = NULL;
    const char *l_wallet_name = NULL;
    const char *l_value_str = NULL;
    const char *l_rate_str = NULL;
    const char *l_fee_str = NULL;
    const char *l_url_str = NULL;
    const char *l_port_str = NULL;
    uint16_t l_port = 0;

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token_sell", &l_token_sell);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token_buy", &l_token_buy);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &l_value_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-rate", &l_rate_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &l_fee_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-url", &l_url_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-port", &l_port_str);

    if (!l_net_name) {
        printf("xchange_create requires parameter '-net'");
        return -1;
    }

    if (!l_url_str) {
        l_url_str = s_get_net_url(l_net_name);
    }

    if (!l_port_str) {
        l_port = s_get_net_port(l_net_name);
    } else {
        l_port = atoi(l_port_str);
    }

    if (!l_token_buy) {
        printf("xchange_create requires parameter '-token_buy'");
        return -1;
    }

    if (!l_token_sell) {
        printf("xchange_create requires parameter '-token_sell'");
        return -1;
    }

    if (!l_wallet_name) {
        printf("xchange_create requires parameter '-w'");
        return -1;
    }

    if (!l_value_str) {
        printf("xchange_create requires parameter '-value'");
        return -1;
    }

    if (!l_rate_str) {
        printf("xchange_create requires parameter '-rate'");
        return -1;
    }

    if (!l_fee_str) {
        printf("xchange_create requires parameter '-fee'");
        return -1;
    }

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, arg_wallets_path, NULL);
    if(!l_wallet) {
        printf("wallet %s does not exist", l_wallet_name);
        return -1;
    }


    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    uint256_t l_rate = dap_chain_balance_scan(l_rate_str);
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_value) || IS_ZERO_256(l_rate) || IS_ZERO_256(l_fee)) {
        printf("Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        return -1;
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_create_compose(l_net_name, l_token_buy,
                                     l_token_sell, l_value, l_rate, l_fee, l_wallet, l_url_str, l_port);
    json_object *l_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_ret);
    printf("%s", json_object_to_json_string(l_ret));
    json_object_put(l_ret);
    dap_chain_datum_tx_delete(l_tx);
    return 0;
}



int dap_tx_create_compose(int argc, char ** argv) {
    int arg_index = 1;
    const char *addr_base58_to = NULL;
    const char *str_tmp = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_wallet_fee_name = NULL;
    const char * l_token_ticker = NULL;
    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;
    const char * l_url_str = NULL;
    uint16_t l_port = 0;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        printf("Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    if (!l_net_name) {
        printf("tx_create requires parameter '-net'");
        return -1;
    }

    if (!dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_name);
    }
    const char *l_port_str = NULL;
    if (!dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_name);
    } else {
        l_port = atoi(l_port_str);
    }

    uint256_t *l_value = NULL;
    uint256_t l_value_fee = {};
    dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from_wallet", &l_from_wallet_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-wallet_fee", &l_wallet_fee_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-chain", &l_chain_name);

    // Validator's fee
    if (dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &str_tmp)) {
        if (!str_tmp) {
            printf("tx_create requires parameter '-fee'");
            return -1;
        }
        l_value_fee = dap_chain_balance_scan(str_tmp);
    }
    if (IS_ZERO_256(l_value_fee) && (str_tmp && strcmp(str_tmp, "0"))) {
        printf("tx_create requires parameter '-fee' to be valid uint256");
        return -2;
    }

    if (!l_from_wallet_name) {
        printf("tx_create requires parameter '-from_wallet'");
        return -3;
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token", &l_token_ticker);
    if (!l_token_ticker) {
        printf("tx_create requires parameter '-token'");
        return -4;
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-to_addr", &addr_base58_to);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &str_tmp);

    if (!str_tmp) {
        printf("tx_create requires parameter '-value' to be valid uint256 value");
        return -6;
    }
    l_value_el_count = dap_str_symbol_count(str_tmp, ',') + 1;

    if (addr_base58_to)
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
    else 
        l_addr_el_count = l_value_el_count;

    if (addr_base58_to && l_addr_el_count != l_value_el_count) {
        printf("num of '-to_addr' and '-value' should be equal");
        return -5;
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        printf("Can't allocate memory");
        return -6;
    }
    char **l_value_array = dap_strsplit(str_tmp, ",", l_value_el_count);
    if (!l_value_array) {
        DAP_DELETE(l_value);
        printf("Can't read '-to_addr' arg");
        return -7;
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            DAP_DEL_MULTY(l_value_array, l_value);
            printf("tx_create requires parameter '-value' to be valid uint256 value");
            return -8;
        }
    }
    DAP_DELETE(l_value_array);

    if (addr_base58_to) {
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            printf("Can't allocate memory");
            DAP_DELETE(l_value);
            return -9;
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value);
            printf("Can't read '-to_addr' arg");
            return -10;
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                for (size_t j = 0; j < i; ++j) {
                    DAP_DELETE(l_addr_to[j]);
                }
                DAP_DEL_MULTY(l_addr_to, l_addr_base58_to_array, l_value);
                printf("destination address is invalid");
                return -11;
            }
        }
        DAP_DELETE(l_addr_base58_to_array);
    }
    
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, arg_wallets_path, NULL);
    if(!l_wallet) {
        printf("Can't open wallet %s", l_from_wallet_name);
        return -12;
    }


    dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet, s_get_net_id(l_net_name));
    for (size_t i = 0; l_addr_to && i < l_addr_el_count; ++i) {
        if (dap_chain_addr_compare(l_addr_to[i], l_addr_from)) {
            printf("The transaction cannot be directed to the same address as the source.");
            for (size_t j = 0; j < l_addr_el_count; ++j) {
                    DAP_DELETE(l_addr_to[j]);
            }
            DAP_DEL_MULTY(l_addr_to, l_value);
            return -13;
        }
    }


    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create_compose(l_net_name, l_addr_from, l_addr_to, l_token_ticker, l_value, l_value_fee, l_addr_el_count, l_url_str, l_port);

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    dap_chain_datum_tx_delete(l_tx);
    DAP_DEL_MULTY(l_addr_to, l_value, l_addr_from);
    return 0;
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


dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(const char * l_net_name, dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num, const char * a_url_str, uint16_t a_port)
{
    if (!a_addr_from || !a_token_ticker || !a_value) {
        return NULL;
    }

    if (dap_chain_addr_check_sum(a_addr_from)) {
        return NULL;
    }

    for (size_t i = 0; i < a_tx_num; ++i) {
        // if (!a_addr_to || !a_addr_to[i]) {
        //     return NULL;
        // }
        if (a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) {
            return NULL;
        }
        if (IS_ZERO_256(a_value[i])) {
            return NULL;
        }
    }
    const char * l_native_ticker = s_get_native_ticker(l_net_name);
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
    if (!dap_get_remote_net_fee_and_address(l_net_name, &l_net_fee, &l_addr_fee, a_url_str, a_port)) {
        return NULL;
    }

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, l_net_name, &l_outs, &l_outputs_count, a_url_str, a_port)) {
        return NULL;
    }

    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            printf("Not enough funds to pay fee");
            json_object_put(l_outs);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    json_object_put(l_outs);
    if (!l_list_used_out) {
        printf("Not enough funds to transfer");
        return NULL;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
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
                if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to[i], a_value[i]) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            } else {
                if (dap_chain_datum_tx_add_out_without_addr(&l_tx, a_value[i]) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }
                SUM_256_256(l_value_pack, a_value[i], &l_value_pack);
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, l_addr_fee, l_net_fee) == 1)
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
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    } else { // add 'out_ext' items
        for (size_t i = 0; i < a_tx_num; ++i) {
            if (a_addr_to) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            } else {
                if (dap_chain_datum_tx_add_out_ext_item_without_addr(&l_tx, a_value[i], a_token_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
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
                return NULL;
            }
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }
    DAP_DELETE(l_addr_fee);
    return l_tx;
}

dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};

    for (int i = 0; i < a_outputs_count; i++) {
        json_object *l_output = json_object_array_get_idx(a_outputs_array, i);
        
        json_object *l_value_datosi_obj = NULL;
        json_object_object_get_ex(l_output, "value_datosi", &l_value_datosi_obj);
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

        dap_chain_hash_fast_from_str(l_prev_hash_str, &l_item->tx_hash_fast);
        l_item->num_idx_out = l_out_idx;
        l_item->value = l_value;

        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        
        SUM_256_256(l_value_transfer, l_value, &l_value_transfer);

        if (compare256(l_value_transfer, a_value_need) >= 0) {
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
                    if (json_object_object_get_ex(token_obj, "-->Token name", &token_name) && json_object_is_type(token_name, json_type_string)) {
                        const char *token_name_str = json_object_get_string(token_name);
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

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_net_name, const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet, const char * a_url_str, uint16_t a_port){
    if (!a_net_name || !a_token_buy || !a_token_sell || !a_wallet) {
        return NULL; // XCHANGE_CREATE_ERROR_INVALID_ARGUMEN
    }
    if (IS_ZERO_256(a_rate)) {
        return NULL; // XCHANGE_CREATE_ERROR_RATE_IS_ZERO
    }
    if (IS_ZERO_256(a_fee)) {
        return NULL; // XCHANGE_CREATE_ERROR_FEE_IS_ZERO
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        return NULL; // XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO
    }
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;list;coins;-net;%s\"],\"id\": \"2\"}", a_net_name);
    json_object *l_json_coins = dap_request_command_to_rpc(data, a_net_name, a_url_str, a_port);
    if (!l_json_coins) {
        return NULL; // XCHANGE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS
    }
    if (!check_token_in_ledger(l_json_coins, a_token_sell) || !check_token_in_ledger(l_json_coins, a_token_buy)) {
        json_object_put(l_json_coins);
        return NULL; // XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER
    }
    json_object_put(l_json_coins);
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, s_get_net_id(a_net_name));
    snprintf(data, sizeof(data), 
            "{\"method\": \"wallet\",\"params\": [\"wallet;info;-addr;%s;-net;%s\"],\"id\": \"2\"}", 
            dap_chain_addr_to_str(l_wallet_addr), a_net_name);
    DAP_DEL_Z(l_wallet_addr);
    json_object *l_json_outs = dap_request_command_to_rpc(data, a_net_name, a_url_str, a_port);
    uint256_t l_value = get_balance_from_json(l_json_outs, a_token_sell);

    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(s_get_native_ticker(a_net_name), a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            return NULL; // XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = get_balance_from_json(l_json_outs, s_get_native_ticker(a_net_name));
        if (compare256(l_fee_value, a_fee) == -1) {
            return NULL; // XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        return NULL; // XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        return NULL; // XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet, s_get_native_ticker(a_net_name), a_net_name, a_url_str, a_port);
    return l_tx;
}

json_object *dap_get_remote_tx_outs(const char *a_token_ticker, const char *a_net_name,  dap_chain_addr_t * a_addr, const char *a_url_str, uint16_t a_port) { 
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"wallet\",\"params\": [\"wallet;outputs;-addr;%s;-token;%s;-net;%s\"],\"id\": \"1\"}", 
            dap_chain_addr_to_str(a_addr), a_token_ticker, a_net_name);
    json_object *l_json_outs = dap_request_command_to_rpc(data, a_net_name, a_url_str, a_port);
    if (!l_json_outs) {
        return NULL;
    }

    if (!json_object_is_type(l_json_outs, json_type_array)) {
        json_object_put(l_json_outs);
        return NULL;
    }

    if (json_object_array_length(l_json_outs) == 0) {
        json_object_put(l_json_outs);
        return NULL;
    }

    json_object *l_first_array = json_object_array_get_idx(l_json_outs, 0);
    if (!l_first_array || !json_object_is_type(l_first_array, json_type_array)) {
        json_object_put(l_json_outs);
        return NULL;
    }

    json_object *l_first_item = json_object_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        json_object_put(l_json_outs);
        return NULL;
    }

    json_object *l_outs = NULL;
    if (!json_object_object_get_ex(l_first_item, "outs", &l_outs) ||
        !json_object_is_type(l_outs, json_type_array)) {
        json_object_put(l_json_outs);
        return NULL;
    }
    json_object_get(l_outs);
    json_object_put(l_json_outs);
    return l_outs;
}


dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet,
                                                                 const char *a_native_ticker, const char *a_net_name, const char * a_url_str, uint16_t a_port)
{
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }
    const char *l_native_ticker = s_get_native_ticker(a_net_name);
    bool l_single_channel = !dap_strcmp(a_price->token_sell, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer; // how many coins to transfer
    uint256_t l_value_need = a_price->datoshi_sell,
              l_net_fee,
              l_total_fee = a_price->fee,
              l_fee_transfer;
    dap_chain_addr_t * l_addr_net_fee = NULL;
    dap_list_t *l_list_fee_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_net_fee, a_url_str, a_port);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, s_get_net_id(a_net_name));
    dap_chain_addr_t l_seller_addr = *l_wallet_addr;
    json_object *l_outs_native = dap_get_remote_tx_outs(a_native_ticker, a_net_name, l_wallet_addr, a_url_str, a_port);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = dap_get_remote_tx_outs(a_price->token_sell, a_net_name, l_wallet_addr, a_url_str, a_port);
    }
    DAP_DELETE(l_wallet_addr);
    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_count = json_object_array_length(l_outs);

    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            printf("Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_out_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        printf("Not enough funds to transfer");
        json_object_put(l_outs_native);
        json_object_put(l_outs);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        printf("Can't compose the transaction input\n");
        return NULL;
    }
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            dap_chain_datum_tx_delete(l_tx);
            printf("Can't compose the transaction input\n");
            return NULL;
        }
    }

    // add 'out_cond' & 'out' items

    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, s_get_net_id(a_net_name), a_price->datoshi_sell,
                                                                                                s_get_net_id(a_net_name), a_price->token_buy, a_price->rate,
                                                                                                &l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            printf("Can't compose the transaction conditional output\n");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if ((l_single_channel &&
                        dap_chain_datum_tx_add_out_item(&l_tx, l_addr_net_fee, l_net_fee) != 1) ||
                    (!l_single_channel &&
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_net_fee, l_net_fee, l_native_ticker) != 1)) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Cant add network fee output\n");
                return NULL;
            }
        }
        DAP_DELETE(l_addr_net_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Cant add validator's fee output\n");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if ((l_single_channel &&
                        dap_chain_datum_tx_add_out_item(&l_tx, &l_seller_addr, l_value_back) != 1) ||
                    (!l_single_channel &&
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_value_back, a_price->token_sell) != 1)) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Cant add coin back output\n");
                return NULL;
            }
        }
        // Fee coinback
        if (!l_single_channel) {
            uint256_t l_fee_coinback = {};
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_coinback);
            if (!IS_ZERO_256(l_fee_coinback)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_fee_coinback, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    printf("Cant add fee back output\n");
                    return NULL;
                }
            }
        }
    }
    return l_tx;
}

// tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name> -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>
int dap_tx_cond_create_compose(int argc, char ** argv)
{
    int arg_index = 1;
    const char * l_token_ticker = NULL;
    const char * l_wallet_str = NULL;
    const char * l_cert_str = NULL;
    const char * l_value_datoshi_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_unit_str = NULL;
    const char * l_srv_uid_str = NULL;
    uint256_t l_value_datoshi = {};    
    uint256_t l_value_fee = {};
    const char * l_url_str = NULL;
    const char * l_port_str = NULL;
    uint16_t l_port = 0;

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &l_value_datoshi_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &l_value_fee_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-unit", &l_unit_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-url", &l_url_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-port", &l_port_str);

    if(!l_token_ticker) {
        printf("tx_cond_create requires parameter '-token'\n");
        return -2;
    }
    if (!l_wallet_str) {
        printf("tx_cond_create requires parameter '-w'\n");
        return -3;
    }
    if (!l_cert_str) {
        printf("tx_cond_create requires parameter '-cert'\n");
        return -4;
    }
    if(!l_value_datoshi_str) {
        printf("tx_cond_create requires parameter '-value'\n");
        return -5;
    }
    if(!l_value_fee_str){
        printf("tx_cond_create requires parameter '-fee'\n");
        return -6;
    }
    if(!l_net_name) {
        printf("tx_cond_create requires parameter '-net'\n");
        return -7;
    }
    if(!l_url_str) {
        l_url_str = s_get_net_url(l_net_name);
    }
    if(!l_port_str) {
        l_port = s_get_net_port(l_net_name);
    } else {
        l_port = atoi(l_port_str);
    }
    if(!l_unit_str) {
        printf("tx_cond_create requires parameter '-unit'\n");
        return -8;
    }

    if(!l_srv_uid_str) {
        printf("tx_cond_create requires parameter '-srv_uid'\n");
        return -9;
    }
    dap_chain_net_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        printf("Can't find service UID %s\n", l_srv_uid_str);
        return -10;
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)l_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        printf("Can't recognize unit '%s'. Unit must look like { B | SEC }\n", l_unit_str);
        return -11;
    }

    l_value_datoshi = dap_chain_balance_scan(l_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        printf("Can't recognize value '%s' as a number\n", l_value_datoshi_str);
        return -12;
    }

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        printf("Can't recognize value '%s' as a number\n", l_value_fee_str);
        return -13;
    }

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, arg_wallets_path, NULL);
    if(!l_wallet) {
        printf("Can't open wallet '%s'\n", l_wallet_str);
        return -15;
    }

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(l_cert_str);
    if(!l_cert_cond) {
        dap_chain_wallet_close(l_wallet);
        printf("Can't find cert '%s'\n", l_cert_str);
        return -16;
    }

    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_enc_key_delete(l_key_from);
        printf("Cert '%s' doesn't contain a valid public key\n", l_cert_str);
        return -17;
    }

    uint256_t l_value_per_unit_max = {};
    dap_chain_datum_tx_t *l_tx = dap_chain_mempool_tx_create_cond_compose(l_net_name, l_key_from, l_key_cond, l_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_url_str, l_port);
    
    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    dap_chain_datum_tx_delete(l_tx);
    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_key_from);
    DAP_DELETE(l_key_cond);
    return 0;
}


dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(const char *a_net_name,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, const char *a_url_str, uint16_t a_port)
{
    // check valid param
    if (!a_net_name || !a_key_from || !a_key_cond ||
            !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || IS_ZERO_256(a_value))
        return NULL;

    if (dap_strcmp(s_get_native_ticker(a_net_name), a_token_ticker)) {
        printf("Pay for service should be only in native token ticker\n");
        return NULL;
    }

    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee, a_url_str, a_port);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = {};
    SUM_256_256(a_value, a_value_fee, &l_value_need);
    if (l_net_fee_used) {
        SUM_256_256(l_value_need, l_net_fee, &l_value_need);
    }
    // where to take coins for service
    dap_chain_addr_t l_addr_from;
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, s_get_net_id(a_net_name));
    // list of transaction with 'out' items
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(&l_addr_from, a_token_ticker, a_net_name, &l_outs, &l_outputs_count, a_url_str, a_port)) {
        return NULL;
    }
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    json_object_put(l_outs);
    if(!l_list_used_out) {
        printf("Nothing to transfer (not enough funds)\n");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
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
            printf("Cant add conditional output\n");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, l_addr_fee, l_net_fee) == 1)
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
            if(dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Cant add coin back output\n");
                return NULL;
            }
        }
    }

    return l_tx;
}

// stake_lock hold -net <net_name> -w <wallet_name> -time_staking <YYMMDD> -token <ticker> -value <value> -fee <value>[-chain <chain_name>] [-reinvest <percentage>]
int  dap_cli_hold_compose(int a_argc, char **a_argv)
{
    int arg_index = 1;
    const char *l_net_name = NULL, *l_ticker_str = NULL, *l_coins_str = NULL,
            *l_wallet_str = NULL, *l_cert_str = NULL, *l_chain_id_str = NULL,
            *l_time_staking_str = NULL, *l_reinvest_percent_str = NULL, *l_value_fee_str = NULL;

    const char *l_wallets_path								=	arg_wallets_path;
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value;
    dap_enc_key_t						*l_key_from;
    dap_chain_wallet_t					*l_wallet;
    dap_chain_addr_t					*l_addr_holder;
    const char                          *l_url_str = NULL;
    uint16_t                            l_port = 0;

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }


    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type, "base58")) {
        printf("Error: Invalid hash type argument\n");
        return -1;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name) || NULL == l_net_name) {
        printf("Error: Missing or invalid network argument\n");
        return -2;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_ticker_str) || NULL == l_ticker_str || dap_strlen(l_ticker_str) > 8) {
        printf("Error: Missing or invalid token argument\n");
        return -3;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_name);
    }

    const char *l_port_str = NULL;
    if (!dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_name);
    } else {
        l_port = atoi(l_port_str);
    }

    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;list;coins;-net;%s\"],\"id\": \"2\"}", l_net_name);
    json_object *l_json_coins = dap_request_command_to_rpc(data, l_net_name, l_url_str, l_port);
    if (!l_json_coins) {
        return -4;
    }
    if (!check_token_in_ledger(l_json_coins, l_ticker_str)) {
        printf("Error: Invalid token '%s'\n", l_ticker_str);
        return -4;
    }

    if ((!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-coins", &l_coins_str) || NULL == l_coins_str) &&
            (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_coins_str) || NULL == l_coins_str)) {
        printf("Error: Missing coins or value argument\n");
        return -5;
    }

    if (IS_ZERO_256((l_value = dap_chain_balance_scan(l_coins_str)))) {
        printf("Error: Invalid coins format\n");
        return -6;
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);

    if (!check_token_in_ledger(l_json_coins, l_delegated_ticker_str)) {
        printf("Error: No delegated token found\n");
        return -7;
    }
    json_object_put(l_json_coins);

    uint256_t l_emission_rate = dap_chain_coins_to_balance("0.001");  // TODO 16126
    // uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);
    // if (IS_ZERO_256(l_emission_rate)) {
    //     printf("Error: Invalid token emission rate\n");
    //     return -8;
    // }

    if (MULT_256_COIN(l_value, l_emission_rate, &l_value_delegated) || IS_ZERO_256(l_value_delegated)) {
        printf("Error: Invalid coins format\n");
        return -9;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_id", &l_chain_id_str);
    if (!l_chain_id_str) {
        printf("Error: Missing or invalid chain_id argument\n");
        return -10;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str) || !l_wallet_str) {
        printf("Error: Missing wallet argument\n");
        return -11;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str) || !l_value_fee_str) {
        printf("Error: Missing fee argument\n");
        return -12;
    }

    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(l_value_fee_str)))) {
        printf("Error: Invalid fee format\n");
        return -13;
    }

    // Read time staking
    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-time_staking", &l_time_staking_str) || !l_time_staking_str) {
        printf("Error: Missing time staking argument\n");
        return -14;
    }

    if (dap_strlen(l_time_staking_str) != 6) {
        printf("Error: Invalid time staking format\n");
        return -15;
    }

    char l_time_staking_month_str[3] = {l_time_staking_str[2], l_time_staking_str[3], 0};
    int l_time_staking_month = atoi(l_time_staking_month_str);
    if (l_time_staking_month < 1 || l_time_staking_month > 12) {
        printf("Error: Invalid time staking month\n");
        return -16;
    }

    char l_time_staking_day_str[3] = {l_time_staking_str[4], l_time_staking_str[5], 0};
    int l_time_staking_day = atoi(l_time_staking_day_str);
    if (l_time_staking_day < 1 || l_time_staking_day > 31) {
        printf("Error: Invalid time staking day\n");
        return -17;
    }

    l_time_staking = dap_time_from_str_simplified(l_time_staking_str);
    if (0 == l_time_staking) {
        printf("Error: Invalid time staking\n");
        return -18;
    }
    dap_time_t l_time_now = dap_time_now();
    if (l_time_staking < l_time_now) {
        printf("Error: Time staking is in the past\n");
        return -19;
    }
    l_time_staking -= l_time_now;

    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-reinvest", &l_reinvest_percent_str) && NULL != l_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_coins_to_balance(l_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_coins_to_balance("100.0")) == 1) {
            printf("Error: Invalid reinvest percentage\n");
            return -20;
        }
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(l_reinvest_percent_str);
            if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100) {
                printf("Error: Invalid reinvest percentage\n");
                return -21;
            }
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
    }

    if(NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path, NULL))) {
        printf("Error: Unable to open wallet '%s'\n", l_wallet_str);
        return -22;
    }


    if (NULL == (l_addr_holder = dap_chain_wallet_get_addr(l_wallet, s_get_net_id(l_net_name)))) {
        dap_chain_wallet_close(l_wallet);
        printf("Error: Unable to get wallet address for '%s'\n", l_wallet_str);
        return -24;
    }

    snprintf(data, sizeof(data), 
        "{\"method\": \"wallet\",\"params\": [\"wallet;info;-addr;%s;-net;%s\"],\"id\": \"2\"}", 
        dap_chain_addr_to_str(l_addr_holder), l_net_name);
    DAP_DEL_Z(l_addr_holder);

    json_object *l_json_outs = dap_request_command_to_rpc(data, l_net_name, l_url_str, l_port);
    uint256_t l_value_balance = get_balance_from_json(l_json_outs, l_ticker_str);
    json_object_put(l_json_outs);
    if (compare256(l_value_balance, l_value) == -1) {
        dap_chain_wallet_close(l_wallet);
        printf("Error: Insufficient funds in wallet\n");
        return -23;
    }

    l_key_from = dap_chain_wallet_get_key(l_wallet, 0);

    // Make transfer transaction
    dap_chain_datum_tx_t *l_tx = dap_stake_lock_datum_create_compose(l_net_name, l_key_from,
                                                           l_ticker_str, l_value, l_value_fee,
                                                           l_time_staking, l_reinvest_percent,
                                                           l_delegated_ticker_str, l_value_delegated, l_chain_id_str, l_url_str, l_port);

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    dap_chain_datum_tx_delete(l_tx);

    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_key_from);
    
    return 0;
}


dap_chain_datum_tx_t * dap_stake_lock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                                    const char * l_chain_id_str, const char *l_url_str, uint16_t l_port)
{
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // check valid param
    if (!a_net_name || !a_key_from ||
        !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || IS_ZERO_256(a_value))
        return NULL;

    const char *l_native_ticker = s_get_native_ticker(a_net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t * l_addr_fee = NULL;
    dap_chain_addr_t l_addr = {};

    dap_chain_addr_fill_from_key(&l_addr, a_key_from, s_get_net_id(a_net_name));
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee, l_url_str, l_port);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);

    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_net_name, &l_addr, l_url_str, l_port);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs_main = NULL;
    if (!dap_strcmp(a_main_ticker, l_native_ticker)) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_get_remote_tx_outs(a_main_ticker, a_net_name, &l_addr, l_url_str, l_port);
    }
    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_main_count = json_object_array_length(l_outs_main);

    dap_list_t *l_list_fee_out = NULL;
    if (l_main_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            printf("Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs_main);
            return NULL;
        }
    }
    // list of transaction with 'out' items
    dap_list_t * l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        printf("Not enough funds to transfer");
        json_object_put(l_outs_native);
        json_object_put(l_outs_main);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
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
        dap_chain_id_parse(l_chain_id_str, &l_chain_id);
        dap_hash_fast_t l_blank_hash = {};
        dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_blank_hash, a_delegated_ticker_str);
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
    }

    // add 'out_cond' and 'out_ext' items
    {
        uint256_t l_value_pack = {}, l_native_pack = {}; // how much coin add to 'out_ext' items
        dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
                                                        l_uid, a_value, a_time_staking, a_reinvest_percent);
        if (l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond);
            DAP_DEL_Z(l_tx_out_cond);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            printf("Error: Cant add conditional output\n");
            return NULL;
        }

        uint256_t l_value_back = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Error: Cant add network fee output\n");
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
                printf("Error: Cant add validator's fee output\n");
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
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, a_main_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Error: Cant add coin back output for main ticker\n");
                return NULL;
            }
        }
        // fee coin back
        if (!IS_ZERO_256(l_fee_transfer)) {
            SUBTRACT_256_256(l_fee_transfer, l_native_pack, &l_value_back);
            if (!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    printf("Error: Cant add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add delegated token emission 'out_ext'
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, a_delegated_value, a_delegated_ticker_str) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        printf("Error: Cant add delegated token emission output\n");
        return NULL;
    }

    return l_tx;
}


int dap_cli_take_compose(int a_argc, char **a_argv)
{
    int arg_index = 1;
    const char *l_net_str, *l_ticker_str, *l_wallet_str, *l_tx_str, *l_tx_burning_str, *l_chain_id_str, *l_value_fee_str;
    l_net_str = l_ticker_str = l_wallet_str = l_tx_str = l_tx_burning_str = l_chain_id_str = l_value_fee_str = NULL;
    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    int									l_prev_cond_idx		=	0;
    uint256_t							l_value_delegated	= 	{};
    uint256_t                           l_value_fee     	=	{};
    dap_chain_wallet_t					*l_wallet;
    dap_hash_fast_t						l_tx_hash;
    dap_chain_tx_out_cond_t				*l_cond_tx = NULL;
    dap_enc_key_t						*l_owner_key;
    const char                          *l_url_str = NULL;
    uint16_t                            l_port = 0;


    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }


    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        printf("Error: Invalid hash type argument\n");
        return -1;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str) || NULL == l_net_str) {
        printf("Error: Missing or invalid network argument\n");
        return -2;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_str);
    }

    const char *l_port_str = NULL;
    if (!dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_str);
    } else {
        l_port = atoi(l_port_str);
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_id", &l_chain_id_str);
    if (!l_chain_id_str) {
        printf("Error: Missing or invalid chain_id argument\n");
        return -10;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_str) || NULL == l_tx_str) {
        printf("Error: Missing or invalid transaction argument\n");
        return -5;
    }

    if (dap_chain_hash_fast_from_str(l_tx_str, &l_tx_hash)) {
        printf("Error: Invalid transaction hash\n");
        return -6;
    }

    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;info;-hash;%s;-net;%s\"],\"id\": \"1\"}", 
            l_tx_str, l_net_str);
    
    json_object *response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
    if (!response) {
        printf("Error: Failed to get response from remote node\n");
        return -15;
    }
    
    json_object *items = NULL;
    json_object *items_array = json_object_array_get_idx(response, 0);
    if (items_array) {
        items = json_object_object_get(items_array, "ITEMS");
    }
    if (!items) {
        printf("Error: No items found in response\n");
        return -16;
    }
    int items_count = json_object_array_length(items);
    for (int i = 0; i < items_count; i++) {
        json_object *item = json_object_array_get_idx(items, i);
        const char *item_type = json_object_get_string(json_object_object_get(item, "item type"));
        if (dap_strcmp(item_type, "OUT COND") == 0) {
            const char *subtype = json_object_get_string(json_object_object_get(item, "subtype"));
            if (!dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK")) {
                l_cond_tx = DAP_NEW_Z(dap_chain_tx_out_cond_t);
                l_cond_tx->header.item_type = TX_ITEM_TYPE_OUT_COND;
                l_cond_tx->header.value =  dap_chain_balance_scan(json_object_get_string(json_object_object_get(item, "value")));
                l_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
                l_cond_tx->header.srv_uid.uint64 = strtoull(json_object_get_string(json_object_object_get(item, "uid")), NULL, 16);
                l_cond_tx->subtype.srv_stake_lock.time_unlock =  dap_time_from_str_rfc822(json_object_get_string(json_object_object_get(item, "time_unlock")));
                break;
            }
        }
    }
    if (!l_cond_tx) {
        printf("Error: No transaction output condition found\n");
        return -7;
    }


    json_object *spent_outs = json_object_object_get(response, "all OUTs yet unspent");
    const char *spent_outs_value = json_object_get_string(spent_outs);
    if (spent_outs_value && dap_strcmp(spent_outs_value, "yes") != 0) {
        printf("Error: Transaction output item already used\n");
        return -9;
    }

    json_object *response_header_array = json_object_array_get_idx(response, 0);
    if (!response_header_array) {
        printf("Error: Failed to get items array from response\n");
        return -10;
    }

    json_object *token_ticker_obj = json_object_object_get(response_header_array, "token ticker");
    if (!token_ticker_obj) {
        printf("Error: Token ticker not found in response\n");
        return -11;
    }
    l_ticker_str = json_object_get_string(token_ticker_obj);



    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);

    uint256_t l_emission_rate = dap_chain_coins_to_balance("0.001");

    if (IS_ZERO_256(l_emission_rate) ||
        MULT_256_COIN(l_cond_tx->header.value, l_emission_rate, &l_value_delegated) ||
        IS_ZERO_256(l_value_delegated)) {
        printf("Error: Invalid coins format\n");
        return -12;
    }


    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str) || !l_wallet_str) {
        printf("Error: Missing or invalid wallet argument\n");
        return -13;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str) || !l_value_fee_str) {
        printf("Error: Missing or invalid fee argument\n");
        return -14;
    }

    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(l_value_fee_str)))) {
        printf("Error: Invalid fee format\n");
        return -15;
    }

    if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, arg_wallets_path, NULL))) {
        printf("Error: Unable to open wallet\n");
        return -16;
    }

    if (NULL == (l_owner_key = dap_chain_wallet_get_key(l_wallet, 0))) {
        dap_chain_wallet_close(l_wallet);
        printf("Error: Owner key not found\n");
        return -17;
    }

    if (l_cond_tx->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        dap_chain_wallet_close(l_wallet);
        dap_enc_key_delete(l_owner_key);
        printf("Error: Not enough time has passed for unlocking\n");
        return -19;
    }
    dap_chain_datum_tx_t *l_tx = dap_stake_unlock_datum_create_compose(l_net_str, l_owner_key, &l_tx_hash, l_prev_cond_idx,
                                          l_ticker_str, l_cond_tx->header.value, l_value_fee,
                                          l_delegated_ticker_str, l_value_delegated, l_url_str, l_port);

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);


    dap_chain_datum_tx_delete(l_tx);
    dap_enc_key_delete(l_owner_key);

    return 0;
}

dap_chain_datum_tx_t *dap_stake_unlock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                               const char *l_url_str, uint16_t l_port)
{
    // check valid param
    if (!a_net_name | !a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || dap_hash_fast_is_blank(a_stake_tx_hash)) {
        printf("Error: Invalid parameters\n");
        return NULL;
    }

    const char *l_native_ticker = s_get_native_ticker(a_net_name);
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    dap_chain_addr_t l_addr = {};

    dap_chain_addr_fill_from_key(&l_addr, a_key_from, s_get_net_id(a_net_name));
    dap_list_t *l_list_fee_out = NULL, *l_list_used_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee, l_url_str, l_port);

    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_net_name, &l_addr, l_url_str, l_port);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs_delegated = dap_get_remote_tx_outs(a_delegated_ticker_str, a_net_name, &l_addr, l_url_str, l_port);
    if (!l_outs_delegated) {
        return NULL;
    }

    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_delegated_count = json_object_array_length(l_outs_delegated);

    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    if (!IS_ZERO_256(l_total_fee)) {
        if (!l_main_native) {
            l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_total_fee, 
                                                                &l_fee_transfer);
            if (!l_list_fee_out) {
                printf("Not enough funds to pay fee");
                json_object_put(l_outs_native);
                json_object_put(l_outs_delegated);
                return NULL;
            }
        } else if (compare256(a_value, l_total_fee) == -1) {
            printf("Error: Total fee more than stake\n");
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_delegated_value)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_delegated_value, 
                                                               &l_value_transfer);
        if (!l_list_used_out) {
            printf("Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs_delegated);
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
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
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
                printf("Error: Can't add network fee output\n");
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
                printf("Error: Can't add validator's fee output\n");
                return NULL;
            }
        }
        // coin back
        //SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
        if(l_main_native){
            if (SUBTRACT_256_256(a_value, l_value_pack, &l_value_back)) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Error: Can't subtract value pack from value\n");
                return NULL;
            }
            if(!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, a_main_ticker)!=1) {
                    dap_chain_datum_tx_delete(l_tx);
                    printf("Error: Can't add coin back output for main ticker\n");
                    return NULL;
                }
            }
        } else {
            SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, a_value, a_main_ticker)!=1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Error: Can't add coin back output for main ticker\n");
                return NULL;
            }
            else
            {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, l_native_ticker)!=1) {
                    dap_chain_datum_tx_delete(l_tx);
                    printf("Error: Can't add coin back output for native ticker\n");
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
            printf("Error: Can't add burning output for delegated value\n");
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, a_delegated_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, a_delegated_ticker_str) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                printf("Error: Can't add coin back output for delegated ticker\n");
                return NULL;
            }
        }
    }

    return l_tx;
}

uint256_t s_get_key_delegating_min_value(const char *a_net_str, const char *l_url_str, uint16_t l_port){
    uint256_t l_key_delegating_min_value = uint256_0;
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;list;keys;-net;%s\"],\"id\": \"1\"}", 
            a_net_str);
    
    json_object *response = dap_request_command_to_rpc(data, a_net_str, l_url_str, l_port);
    if (!response) {
        printf("Error: Failed to get response from remote node\n");
        return l_key_delegating_min_value;
    }

    json_object *response_array = json_object_array_get_idx(response, 0);
    if (!response_array) {
        printf("Error: Invalid response format\n");
        return l_key_delegating_min_value;
    }

    json_object *summary_obj = json_object_array_get_idx(response_array, json_object_array_length(response_array) - 1);
    if (!summary_obj) {
        printf("Error: Summary object not found in response\n");
        return l_key_delegating_min_value;
    }

    json_object *key_delegating_min_value_obj = json_object_object_get(summary_obj, "key_delegating_min_value");
    if (!key_delegating_min_value_obj) {
        printf("Error: key_delegating_min_value not found in summary\n");
        return l_key_delegating_min_value;
    }

    const char *key_delegating_min_value_str = json_object_get_string(key_delegating_min_value_obj);
    if (!key_delegating_min_value_str) {
        printf("Error: Invalid key_delegating_min_value format\n");
        return l_key_delegating_min_value;
    }

    l_key_delegating_min_value = dap_chain_balance_scan(key_delegating_min_value_str);
    if (IS_ZERO_256(l_key_delegating_min_value)) {
        printf("Error: Unrecognized number in key_delegating_min_value\n");
        return l_key_delegating_min_value;
    }

    return l_key_delegating_min_value;
}


int dap_cli_voting_compose(int a_argc, char **a_argv)
{
    int arg_index = 1;
    const char* l_question_str = NULL;
    const char* l_options_list_str = NULL;
    const char* l_voting_expire_str = NULL;
    const char* l_max_votes_count_str = NULL;
    const char* l_fee_str = NULL;
    const char* l_wallet_str = NULL;
    const char* l_net_str = NULL;
    const char* l_token_str = NULL;
    const char* l_url_str = NULL;
    uint16_t l_port = 0;
    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }
    
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        printf("Voting requires parameter '-net' to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_str);
    }

    const char *l_port_str = NULL;
    if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_str);
    } else {
        l_port = atoi(l_port_str);
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-question", &l_question_str);
    if (!l_question_str){
        printf("Voting requires a question parameter to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_QUESTION_PARAM_MISSING;
    }

    if (strlen(l_question_str) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        printf("The question must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        return -DAP_CHAIN_NET_VOTE_CREATE_QUESTION_CONTAIN_MAX_CHARACTERS;
    }

    dap_list_t *l_options_list = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-options", &l_options_list_str);
    if (!l_options_list_str){
        printf("Voting requires a question parameter to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING;
    }
    // Parse options list
    l_options_list = dap_get_options_list_from_str(l_options_list_str);
    if(!l_options_list || dap_list_length(l_options_list) < 2){
        printf("Number of options must be 2 or greater.\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR;
    }

    if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
        printf("The voting can contain no more than %d options\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);            
        return -DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-expire", &l_voting_expire_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-max_votes_count", &l_max_votes_count_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str){
        printf("Voting requires parameter -fee to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID;
    }
    uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str){
        printf("Voting requires parameter -w to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID;
    }

    dap_time_t l_time_expire = 0;
    if (l_voting_expire_str)
        l_time_expire = dap_time_from_str_rfc822(l_voting_expire_str);
    if (l_voting_expire_str && !l_time_expire){
        printf("Wrong time format. -expire parameter must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT;
    }
    uint64_t l_max_count = 0;
    if (l_max_votes_count_str)
        l_max_count = strtoul(l_max_votes_count_str, NULL, 10);

    bool l_is_delegated_key = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-delegated_key_required", NULL) ? true : false;
    bool l_is_vote_changing_allowed = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-vote_changing_allowed", NULL) ? true : false;
    dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, arg_wallets_path, NULL);
    if (!l_wallet_fee) {
        printf("Wallet %s does not exist\n", l_wallet_str);
        return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_str);
    if (!l_token_str) {
        printf("Command required -token argument");
        return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST;
    }
        
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;list;coins;-net;%s\"],\"id\": \"2\"}", l_net_str);
    json_object *l_json_coins = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
    if (!l_json_coins) {
        printf("Error: Can't get ledger coins list\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS;
    }
    if (!check_token_in_ledger(l_json_coins, l_token_str)) {
        json_object_put(l_json_coins);
        printf("Token %s does not exist\n", l_token_str);
        return -DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN;
    }
    json_object_put(l_json_coins);

    dap_chain_datum_tx_t* l_tx = dap_chain_net_vote_create_compose(l_question_str, l_options_list, l_time_expire, l_max_count,
                                                                l_value_fee, l_is_delegated_key, l_is_vote_changing_allowed, 
                                                                l_wallet_fee, l_net_str, l_token_str, l_url_str, l_port);
    dap_list_free(l_options_list);
    dap_chain_wallet_close(l_wallet_fee);
    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    return 0;
}


dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                              const char *a_net_str, const char *a_token_ticker, const char *l_url_str, uint16_t l_port) {

    if (strlen(a_question) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        return NULL;
    }

    // Parse options list

    if(dap_list_length(a_options) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
        return NULL;
    }

    if (IS_ZERO_256(a_fee)) {
        return NULL;
    }

    dap_chain_addr_t *l_addr_from =  dap_chain_wallet_get_addr(a_wallet, s_get_net_id(a_net_str));

    if(!l_addr_from) {
        return NULL;
    }

    const char *l_native_ticker = s_get_native_ticker(a_net_str);
    uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_str, &l_net_fee, &l_addr_fee, l_url_str, l_port);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(l_addr_from, l_native_ticker, a_net_str, &l_outs, &l_outputs_count, l_url_str, l_port)) {
        return NULL;
    }

    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer);

    json_object_put(l_outs);
    if (!l_list_used_out) {
        printf("Not enough funds to transfer");
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

    // Add options to tsd
    dap_list_t *l_temp = a_options;
    while(l_temp){
        if(strlen((char*)l_temp->data) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH){
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_tx_tsd_t* l_option = dap_chain_datum_voting_answer_tsd_create((char*)l_temp->data, strlen((char*)l_temp->data));
        if(!l_option){
            dap_chain_datum_tx_delete(l_tx);
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
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }

        dap_chain_tx_tsd_t* l_expired_item = dap_chain_datum_voting_expire_tsd_create(l_expired_vote);
        if(!l_expired_item){
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_expired_item);
        DAP_DEL_Z(l_expired_item);
    }

    // Add vote max count if needed
    if (a_max_vote != 0) {
        dap_chain_tx_tsd_t* l_max_votes_item = dap_chain_datum_voting_max_votes_count_tsd_create(a_max_vote);
        if(!l_max_votes_item){
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_max_votes_item);
        DAP_DEL_Z(l_max_votes_item);
    }

    if (a_delegated_key_required) {
        dap_chain_tx_tsd_t* l_delegated_key_req_item = dap_chain_datum_voting_delegated_key_required_tsd_create(true);
        if(!l_delegated_key_req_item){
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_delegated_key_req_item);
        DAP_DEL_Z(l_delegated_key_req_item);
    }

    if(a_vote_changing_allowed){
        dap_chain_tx_tsd_t* l_vote_changing_item = dap_chain_datum_voting_vote_changing_allowed_tsd_create(true);
        if(!l_vote_changing_item){
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_vote_changing_item);
        DAP_DEL_Z(l_vote_changing_item);
    }
    if (a_token_ticker) {
        dap_chain_tx_tsd_t *l_voting_token_item = dap_chain_datum_voting_token_tsd_create(a_token_ticker);
        if (!l_voting_token_item) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_voting_token_item);
        DAP_DEL_Z(l_voting_token_item);
    }

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
    dap_list_free_full(l_list_used_out, NULL);
    uint256_t l_value_pack = {};
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, l_addr_fee, l_net_fee) == 1)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }


    return l_tx;
}

/**
int dap_cli_vote_compose(int a_argc, char **a_argv){
    const char* l_cert_name = NULL;
    const char* l_fee_str = NULL;
    const char* l_wallet_str = NULL;
    const char* l_hash_str = NULL;
    const char* l_option_idx_str = NULL;
    const char* l_net_str = NULL;
    int arg_index = 1;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    if(!l_net_str) {
        printf("command requires parameter '-net'\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING;
    } 

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
    if(!l_hash_str){
        printf("Command 'vote' require the parameter -hash\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_HASH_NOT_FOUND;
    }

    dap_hash_fast_t l_voting_hash = {};
    if (dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash)) {
        printf("Hash string is not recognozed as hex of base58 hash\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_HASH_INVALID;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
    dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_name);
    if (l_cert_name){
        if (l_cert == NULL) {
            printf("Can't find \"%s\" certificate\n", l_cert_name);
            return -DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_CERT;
        }
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str){
        printf("Command 'vote' requires paramete -fee to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_NOT_VALID;
    }
    uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_value_fee)) {
        printf("command requires parameter '-fee' to be valid uint256\n");            
        return -DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_BAD_TYPE;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str){
        printf("Command 'vote' requires parameter -w to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_WALLET_PARAM_NOT_VALID;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-option_idx", &l_option_idx_str);
    if (!l_option_idx_str){
        printf("Command 'vote' requires parameter -option_idx to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_OPTION_IDX_PARAM_NOT_VALID;
    }

    const char *arg_wallets_path = dap_chain_wallet_get_path(g_config);
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, arg_wallets_path,NULL);
    if (!l_wallet) {
        printf("Wallet %s does not exist\n", l_wallet_str);
        return -DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST;
    }

    uint64_t l_option_idx_count = strtoul(l_option_idx_str, NULL, 10);

    char *l_hash_tx;

    int res = dap_chain_net_vote_voting_compose(l_cert, l_value_fee, l_wallet, l_voting_hash, l_option_idx_count,
                                        l_net_str, &l_hash_tx);
    dap_chain_wallet_close(l_wallet);

    return res;
}


int dap_chain_net_vote_voting_compose(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_hash_fast_t a_hash,
                              uint64_t a_option_idx, const char *a_net_str, const char *a_hash_out_type,
                              char **a_hash_tx_out) {
    const char * l_hash_str = dap_chain_hash_fast_to_str_static(&a_hash);
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"voting\",\"params\": [\"voting;dump;-hash;%s\"],\"id\": \"2\"}", l_hash_str);
    json_object *l_json_voting = dap_request_command_to_rpc(data);
    if (!l_json_voting) {
        printf("Error: Can't get voting info\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS;
    }

    
    json_object *l_voting_info = json_object_array_get_idx(l_json_voting, 0);
    if (!l_voting_info) {
        printf("Error: Can't get voting info from JSON\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS;
    }

    const char *l_voting_tx = json_object_get_string(json_object_object_get(l_voting_info, "voting_tx"));
    const char *l_expiration_str = json_object_get_string(json_object_object_get(l_voting_info, "expiration"));
    const char *l_status = json_object_get_string(json_object_object_get(l_voting_info, "status"));
    int l_votes_max = json_object_get_int(json_object_object_get(l_voting_info, "votes_max"));
    int l_votes_available = json_object_get_int(json_object_object_get(l_voting_info, "votes_available"));
    bool l_vote_changed = json_object_get_boolean(json_object_object_get(l_voting_info, "can_change_status"));
    bool l_delegated_key_required = json_object_get_boolean(json_object_object_get(l_voting_info, "delegated_key_required"));

    json_object *l_results = json_object_object_get(l_voting_info, "results");
    if (!l_results) {
        printf("Error: Can't get results from JSON\n");
        return -DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS;
    }

    int l_results_count = json_object_array_length(l_results);


    if (l_votes_max && l_votes_max <= l_results_count)
        return DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES;

    if (l_expiration_str) {
        struct tm tm;
        strptime(l_expiration_str, "%a, %d %b %Y %H:%M:%S %z", &tm);
        time_t l_expiration_time = mktime(&tm);
        if (l_expiration_time && dap_time_now() > l_expiration_time)
            return DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED;
    }

    dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(a_wallet, s_get_net_id(a_net_str));
    if (!l_addr_from)
        return DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID;

    dap_hash_fast_t l_pkey_hash = {0};
    if (l_delegated_key_required) {
        if (!a_cert)
            return DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED;
        if (dap_cert_get_pkey_hash(a_cert, &l_pkey_hash))
            return DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT;
        char data[512];
        snprintf(data, sizeof(data), 
                "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;list;keys;-net;%s\"],\"id\": \"1\"}", a_net_str);
        json_object *l_json_coins = dap_request_command_to_rpc(data);
        if (!l_json_coins) {
            printf("Error: Failed to retrieve coins from ledger\n");
            return -4;
        }
        const char * l_hash_fast_str[DAP_HASH_FAST_STR_SIZE] = {};
        dap_chain_hash_fast_from_str(l_hash_fast_str, &l_pkey_hash);
        if (!l_hash_fast_str) {
            printf("Error: Can't covert l_pkey_hash to str");
            return -5;
        }
        int items_count = json_object_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            json_object *item = json_object_array_get_idx(l_json_coins, i);
            const char *pkey_hash_str = json_object_get_string(json_object_object_get(item, "pkey_hash"));
            if (l_hash_fast_str && !dap_strcmp(l_hash_fast_str, pkey_hash_str)) {
                const char *tx_hash_str = json_object_get_string(json_object_object_get(item, "tx_hash"));
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_pkey_hash)) {
                    printf("Invalid transaction hash format\n");
                    return DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            printf("Specified certificate/pkey hash is not delegated nor this delegating is approved. Try to invalidate with tx hash instead\n");
            return -9;
        }


    } else
        l_pkey_hash = l_addr_from->data.hash_fast;


    const char *l_token_ticker = json_object_get_string(json_object_object_get(l_voting_info, "token"));
    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_value_transfer, l_fee_transfer;
    dap_chain_addr_t* l_addr_fee = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_str, &l_net_fee, &l_addr_fee);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    bool l_native_tx = !dap_strcmp(l_token_ticker, s_get_native_ticker(a_net_str));

    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(l_addr_from, l_token_ticker, a_net_str, &l_outs, &l_outputs_count)) {
        return -11;
    }

    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer);
    json_object_put(l_outs);
    if (!l_list_used_out) {
        printf("Not enough funds to transfer");
        return DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER;
    }

    // check outputs UTXOs
    uint256_t l_value_transfer_new = {};
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(l_list_used_out, it, tmp) {
        dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)it->data;
        if (s_datum_tx_voting_coin_check_spent(a_net, a_hash, l_out->tx_hash_fast, l_out->num_idx_out,
                                               l_vote_changed ? &l_pkey_hash : NULL)) {
            l_list_used_out = dap_list_delete_link(l_list_used_out, it);
            continue;
        }
        if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new))
            return DAP_CHAIN_NET_VOTE_VOTING_INTEGER_OVERFLOW;
    }

    if (IS_ZERO_256(l_value_transfer_new) || (l_native_tx && compare256(l_value_transfer_new, l_total_fee) <= 0))
        return DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING;

    l_value_transfer = l_value_transfer_new;

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    uint256_t l_value_back = l_value_transfer, l_fee_back = {};
    if (!l_native_tx) {
        dap_list_t *l_list_fee_outs = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_net->pub.native_ticker, l_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_outs) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER;
        }
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_outs);
        assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
        dap_list_free_full(l_list_fee_outs, NULL);
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
    } else
        SUBTRACT_256_256(l_value_transfer, l_total_fee, &l_value_back);

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
    dap_list_free_full(l_list_used_out, NULL);

    // Add vote item
    if (a_option_idx > dap_list_length(l_voting->voting_params.option_offsets_list)){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX;
    }
    dap_chain_tx_vote_t* l_vote_item = dap_chain_datum_tx_item_vote_create(&a_hash, &a_option_idx);
    if(!l_vote_item){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);

    // add out conds items
    dap_list_t *l_outs = dap_ledger_get_list_tx_cond_outs(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL, l_token_ticker, l_addr_from);
    for (dap_list_t *it = l_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)it->data;
        if (s_datum_tx_voting_coin_check_cond_out(a_net, a_hash, l_out_item->tx_hash_fast, l_out_item->num_idx_out,
                                                  l_vote_changed ? &l_pkey_hash : NULL) != 0)
            continue;
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if(!l_item){
            dap_chain_datum_tx_delete(l_tx);

            dap_list_free_full(l_outs, NULL);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_item);
        DAP_DEL_Z(l_item);
    }
    dap_list_free_full(l_outs, NULL);

    // Network fee
    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
    }

    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
    }

    // coin back
    if (!IS_ZERO_256(l_value_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_token_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
    }
    if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_fee_back, a_net->pub.native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
    }

    dap_enc_key_t *l_priv_key = dap_chain_wallet_get_key(a_wallet, 0);
    // add 'sign' items with wallet sign
    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_priv_key);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
    }
    dap_enc_key_delete(l_priv_key);

    // add 'sign' items with delegated key if needed
    if (a_cert && dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    dap_chain_t* l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);

    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    if (l_ret) {
        *a_hash_tx_out = l_ret;
        return DAP_CHAIN_NET_VOTE_VOTING_OK;
    } else {
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL;
    }
}

*/


int dap_cli_srv_stake_invalidate_compose(int a_argc, char **a_argv)
{
    const char *l_net_str = NULL,
               *l_wallet_str = NULL,
               *l_cert_str = NULL,
               *l_fee_str = NULL,
               *l_tx_hash_str = NULL,
               *l_url_str = NULL,
               *l_port_str = NULL;
    uint16_t l_port = 0;
               
    int l_arg_index = 1;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        printf("Command 'invalidate' requires parameter -net\n");
        return -1;
    }
    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_str);
    }
    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_str);
    } else {
        l_port = atoi(l_port_str);
    }

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    uint256_t l_fee = {};
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        printf("Command 'invalidate' requires parameter -w\n");
        return -1;
    }
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        printf("Command 'delegate' requires parameter -fee\n");
        return -1;
    }
    l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        printf("Unrecognized number in '-fee' param\n");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if (!l_tx_hash_str) {
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            printf("Command 'invalidate' requires parameter -tx or -cert\n");
            return -1;
        }
    }

    dap_hash_fast_t l_tx_hash = {};
    if (l_tx_hash_str) {
        dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        if (l_cert_str) {
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                printf("Specified certificate not found\n");
                return -4;
            }
            if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
                printf("It is not possible to invalidate a stake using a public key.\n");
                return -5;
            }
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, s_get_net_id(l_net_str))) {
                printf("Specified certificate is wrong\n");
                return -6;
            }
        }
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_signing_addr);

        char data[512];
        snprintf(data, sizeof(data), 
                "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;list;keys;-net;%s\"],\"id\": \"1\"}", l_net_str);
        json_object *l_json_coins = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
        if (!l_json_coins) {
            printf("Error: Failed to retrieve coins from ledger\n");
            return -4;
        }
        
        int items_count = json_object_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            json_object *item = json_object_array_get_idx(l_json_coins, i);
            const char *node_addr_str = json_object_get_string(json_object_object_get(item, "node_addr"));
            if (node_addr_str && !dap_strcmp(l_addr_str, node_addr_str)) {
                const char *tx_hash_str = json_object_get_string(json_object_object_get(item, "tx_hash"));
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_tx_hash)) {
                    printf("Invalid transaction hash format\n");
                    json_object_put(l_json_coins);
                    return -8;
                }
                found = true;
                break;
            }
        }
        json_object_put(l_json_coins);
        if (!found) {
            printf("Specified address is not delegated nor this delegating is approved. Try to invalidate with tx hash instead\n");
            return -9;
        }
    }

    const char *l_tx_hash_str_tmp = l_tx_hash_str ? l_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);

    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;info;-hash;%s;-net;%s\"],\"id\": \"1\"}", l_tx_hash_str_tmp, l_net_str);
    json_object *l_json_response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
    if (!l_json_response) {
        printf("Error: Failed to retrieve transaction info from ledger\n");
        return -4;
    }

    json_object *l_json_items = json_object_array_get_idx(l_json_response, 0);
    l_json_items = json_object_object_get(l_json_items, "ITEMS");
    bool has_delegate_out = false;
    if (l_json_items) {
        int items_count = json_object_array_length(l_json_items);
        for (int i = 0; i < items_count; i++) {
            json_object *item = json_object_array_get_idx(l_json_items, i);
            const char *item_type = json_object_get_string(json_object_object_get(item, "item type"));
            if (item_type && strcmp(item_type, "OUT COND") == 0) {
                const char *subtype = json_object_get_string(json_object_object_get(item, "subtype"));
                if (subtype && strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE") == 0) {
                    has_delegate_out = true;
                    break;
                }
            }
        }
    }

    if (!has_delegate_out) {
        printf("Transaction %s does not have a delegate out\n", l_tx_hash_str_tmp);
        json_object_put(l_json_response);
        return -11;
    }

    json_object *l_json_spents = json_object_object_get(l_json_response, "Spent OUTs");
    if (l_json_spents) {
        int spents_count = json_object_array_length(l_json_spents);
        for (int i = 0; i < spents_count; i++) {
            json_object *spent_item = json_object_array_get_idx(l_json_spents, i);
            const char *spent_by_tx = json_object_get_string(json_object_object_get(spent_item, "is spent by tx"));
            if (spent_by_tx) {
                if (dap_chain_hash_fast_from_str(spent_by_tx, &l_tx_hash)) {
                    printf("Invalid transaction hash format in response\n");
                    json_object_put(l_json_response);
                    return -8;
                }
                l_tx_hash_str_tmp = dap_hash_fast_to_str_static(&l_tx_hash);
                snprintf(data, sizeof(data), 
                        "{\"method\": \"ledger\",\"params\": [\"ledger;tx;info;-hash;%s;-net;%s\"],\"id\": \"1\"}", l_tx_hash_str_tmp, l_net_str);
                json_object *l_json_prev_tx = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
                if (!l_json_prev_tx) {
                    printf("Previous transaction %s is not found\n", l_tx_hash_str_tmp);
                    json_object_put(l_json_response);
                    return -12;
                }
                json_object_put(l_json_prev_tx);
                break; 
            }
        }
    }

    if (l_tx_hash_str) {
        char data[512];
        snprintf(data, sizeof(data), 
                "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;list;tx;-net;%s\"],\"id\": \"1\"}", l_net_str);
        json_object *l_json_coins = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
        if (!l_json_coins) {
            printf("Error: Failed to retrieve coins from ledger\n");
            json_object_put(l_json_response);
            return -4;
        }

        bool tx_exists = false;
        int tx_count = json_object_array_length(l_json_coins);
        for (int i = 0; i < tx_count; i++) {
            json_object *tx_item = json_object_array_get_idx(l_json_coins, i);
            const char *tx_hash = json_object_get_string(json_object_object_get(tx_item, "tx_hash"));
            if (tx_hash && strcmp(tx_hash, l_tx_hash_str_tmp) == 0) {
                printf("Error: Transaction %s already exists in the ledger\n", l_tx_hash_str_tmp);
                json_object_put(l_json_coins);
                json_object_put(l_json_response);
                return -13;
            }
        }
        json_object_put(l_json_coins);
    }
    dap_chain_datum_tx_t *l_tx = NULL;

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallet_path,NULL);
    if (!l_wallet) {
        printf("Specified wallet not found\n");
        json_object_put(l_json_response);
        return -14;
    }
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    l_tx = dap_stake_tx_invalidate_compose(l_net_str, &l_tx_hash, l_fee, l_enc_key, l_url_str, l_port);
    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_enc_key);
    json_object_put(l_json_response);
    return 0;
}


dap_chain_datum_tx_t *dap_stake_tx_invalidate_compose(const char *a_net_str, dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_enc_key_t *a_key, const char *l_url_str, uint16_t l_port)
{ 
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;info;-need_sign;-hash;%s;-net;%s\"],\"id\": \"1\"}", 
            dap_hash_fast_to_str_static(a_tx_hash), a_net_str);
    
    json_object *response = dap_request_command_to_rpc(data, a_net_str, l_url_str, l_port);
    if (!response) {
        printf("Error: Failed to get response from remote node\n"); 
        return NULL;
    }
    json_object *l_items_array = json_object_array_get_idx(response, 0);
    l_items_array = json_object_object_get(l_items_array, "ITEMS");
    if (!l_items_array) {
        printf("Error: ITEMS array not found in JSON response\n");
        json_object_put(response);
        return NULL;
    }

    json_object *l_unspent_outs = json_object_object_get(response, "all OUTs yet unspent");
    if (l_unspent_outs) {
        const char *all_unspent = json_object_get_string(l_unspent_outs);
        if (all_unspent && strcmp(all_unspent, "yes") == 0) {
            printf("Error: All outputs are spent\n");
            json_object_put(response);
            return NULL;
        }
    }

    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    const char * l_tx_prev_hash = NULL;
    int l_prev_cond_idx = 0;

    size_t items_count = json_object_array_length(l_items_array);
    for (size_t i = 0; i < items_count; i++) {
        json_object *l_item = json_object_array_get_idx(l_items_array, i);
        const char *item_type = json_object_get_string(json_object_object_get(l_item, "item type"));

        if (item_type && strcmp(item_type, "OUT COND") == 0) {
            l_tx_out_cond = DAP_NEW_Z(dap_chain_tx_out_cond_t);
            l_tx_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
            l_tx_out_cond->header.value = dap_uint256_scan_uninteger(json_object_get_string(json_object_object_get(l_item, "value")));
        } else if (item_type && strcmp(item_type, "IN COND") == 0) {
            l_tx_prev_hash = json_object_get_string(json_object_object_get(l_item, "Tx_prev_hash"));
            if (!l_tx_prev_hash) {
                printf("Error: Tx_prev_hash not found in ITEMS array\n");
                json_object_put(response);
                DAP_DELETE(l_tx_out_cond);
                return NULL;
            }
            l_prev_cond_idx = json_object_get_int(json_object_object_get(l_item, "Tx_out_prev_idx"));
            snprintf(data, sizeof(data), 
                    "{\"method\": \"ledger\",\"params\": [\"ledger;info;-hash;%s;-net;%s\"],\"id\": \"1\"}", 
                    l_tx_prev_hash, a_net_str);
            
            json_object *response_cond = dap_request_command_to_rpc(data, a_net_str, l_url_str, l_port);
            if (!response_cond) {
                printf("Error: Request conditional transaction failed\n"); 
                json_object_put(response);
                DAP_DELETE(l_tx_out_cond);
                return NULL;
            }
            json_object_put(response_cond);
        }
    }

    if (!l_tx_out_cond || !l_tx_prev_hash) {
        printf("Error: Required conditional transaction structures not found\n");
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        return NULL;
    }

    json_object *l_sig_item = NULL;
    for (size_t i = 0; i < items_count; i++) {
        json_object *l_item = json_object_array_get_idx(l_items_array, i);
        const char *item_type = json_object_get_string(json_object_object_get(l_item, "item type"));
        if (item_type && strcmp(item_type, "SIG") == 0) {
            l_sig_item = l_item;
            break;
        }
    }

    if (!l_sig_item) {
        printf("Error: SIG item not found in ITEMS array\n");
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        return NULL;
    }

    const char *l_sign_b64_str = json_object_get_string(json_object_object_get(l_sig_item, "sig_b64"));
    if (!l_sign_b64_str) {
        printf("Error: Can't get base64-encoded sign from SIG item\n");
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        return NULL;
    }

    int64_t l_sign_b64_strlen = json_object_get_string_len(json_object_object_get(l_sig_item, "sig_b64"));
    int64_t l_sign_decoded_size = DAP_ENC_BASE64_DECODE_SIZE(l_sign_b64_strlen);
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t, sizeof(dap_chain_tx_sig_t) + l_sign_decoded_size);
    *l_tx_sig = (dap_chain_tx_sig_t) {
        .header = {
            .type = TX_ITEM_TYPE_SIG, .version = 1,
            .sig_size = dap_enc_base64_decode(l_sign_b64_str, l_sign_b64_strlen, l_tx_sig->sig, DAP_ENC_DATA_TYPE_B64_URLSAFE)
        }
    };

    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_sign(&l_owner_addr, l_sign, s_get_net_id(a_net_str));
    dap_chain_addr_t l_wallet_addr;
    dap_chain_addr_fill_from_key(&l_wallet_addr, a_key, s_get_net_id(a_net_str));
    if (!dap_chain_addr_compare(&l_owner_addr, &l_wallet_addr)) {
        printf("Trying to invalidate delegating tx with not a owner wallet\n");
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        return NULL;
    }
    
    const char *l_native_ticker = s_get_native_ticker(a_net_str);

    json_object *l_json_tiker = json_object_array_get_idx(response, 0);
    json_object *token_ticker_obj = json_object_object_get(l_json_tiker, "Token_ticker");
    if (!token_ticker_obj) {
        token_ticker_obj = json_object_object_get(l_json_tiker, "token ticker");
        if (!token_ticker_obj) {
            printf("Error: Token ticker not found in response\n");
            json_object_put(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            return NULL;
        }
    }
    const char *l_delegated_ticker = json_object_get_string(token_ticker_obj);

    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_net_str, &l_owner_addr, l_url_str, l_port);
    if (!l_outs_native) {
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        return NULL;
    }

    int l_out_native_count = json_object_array_length(l_outs_native);
    uint256_t l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t*l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_str, &l_net_fee, &l_net_fee_addr, l_url_str, l_port);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_fee_out = NULL; 
    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_fee_total, 
                                                                &l_fee_transfer);
    if (!l_list_fee_out) {
        printf("Not enough funds to pay fee");
        json_object_put(l_outs_native);
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_prev_cond_idx, 0);

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        printf("Can't compose the transaction input\n");
        dap_chain_datum_tx_delete(l_tx);
        json_object_put(l_outs_native);
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        return NULL;
    }

    // add 'out_ext' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value, l_delegated_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        printf("Cant add returning coins output\n");
        json_object_put(l_outs_native);
        json_object_put(response);
        DAP_DELETE(l_tx_out_cond);
        DAP_DELETE(l_tx_sig);
        return NULL;
    }
    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            json_object_put(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            json_object_put(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            return NULL;
        }
    }
    // fee coin back
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            json_object_put(l_outs_native);
            json_object_put(response);
            DAP_DELETE(l_tx_out_cond);
            DAP_DELETE(l_tx_sig);
            return NULL;
        }
    }
    json_object_put(l_outs_native);
    json_object_put(response);
    DAP_DELETE(l_tx_out_cond);
    DAP_DELETE(l_tx_sig);
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
            l_order->price = dap_uint256_scan_uninteger(json_object_get_string(json_object_object_get(order_obj, "price datoshi")));
            strncpy(l_order->price_ticker, json_object_get_string(json_object_object_get(order_obj, "price token")), DAP_CHAIN_TICKER_SIZE_MAX);
            l_order->units = json_object_get_int(json_object_object_get(order_obj, "units"));
            l_order->price_unit = dap_chain_net_srv_price_unit_uid_from_str(json_object_get_string(json_object_object_get(order_obj, "price unit")));
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
                a_sovereign_addr = dap_chain_addr_from_str(sovereign_addr_str);
            }
            break;
        }
    }
    return l_order;
}

dap_chain_net_srv_order_t* dap_get_remote_srv_order(const char* l_net_str, const char* l_order_hash_str, uint256_t* a_tax,
                                                    uint256_t* a_value_max, dap_chain_addr_t* a_sovereign_addr, uint256_t* a_sovereign_tax,
                                                    const char* l_url_str, uint16_t l_port){
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;order;list;staker;-net;%s\"],\"id\": \"1\"}", 
            l_net_str);
    json_object *response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
    if (!response) {
        printf("Error: Failed to get response from remote node\n");
        return NULL;
    }

    dap_chain_net_srv_order_t *l_order = dap_check_remote_srv_order(l_net_str, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
    json_object_put(response);

    if (!l_order) {
        snprintf(data, sizeof(data), 
                "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;order;list;validator;-net;%s\"],\"id\": \"1\"}", 
                l_net_str);
        response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
        if (!response) {
            printf("Error: Failed to get response from remote node\n");
            return NULL;
        }
        l_order = dap_check_remote_srv_order(l_net_str, l_order_hash_str, a_tax, a_value_max, a_sovereign_addr, a_sovereign_tax, response);
        json_object_put(response);
    }
    return l_order;
}

dap_sign_t* dap_get_remote_srv_order_sign(const char* l_net_str, const char* l_order_hash_str,
                                                    const char* l_url_str, uint16_t l_port){
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"net_srv\",\"params\": [\"net_srv;-net;%s;order;dump;-hash;%s;-need_sign\"],\"id\": \"1\"}", 
            l_net_str, l_order_hash_str);
    json_object *response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
    if (!response) {
        printf("Error: Failed to get response from remote node\n");
        return NULL;
    }
    json_object *l_response_array = json_object_array_get_idx(response, 0);
    if (!l_response_array) {
        printf("Error: Can't get the first element from the response array\n");
        json_object_put(response);
        return NULL;
    }

    const char *l_sign_b64_str = json_object_get_string(json_object_object_get(l_response_array, "sig_b64"));
    if (!l_sign_b64_str) {
        printf("Error: Can't get base64-encoded sign from SIG item\n");
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

    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
    DAP_DELETE(l_tx_sig);
    json_object_put(response);
    return l_sign;
}




int dap_cli_srv_stake_delegate_compose(int a_argc, char **a_argv)
{
    int l_arg_index = 0;
    const char *l_net_str = NULL,
               *l_wallet_str = NULL,
               *l_cert_str = NULL,
               *l_pkey_str = NULL,
               *l_pkey_full_str = NULL,
               *l_sign_type_str = NULL,
               *l_value_str = NULL,
               *l_fee_str = NULL,
               *l_node_addr_str = NULL,
               *l_order_hash_str = NULL,
               *l_url_str = NULL,
               *l_port_str = NULL;
    int l_port = 0;
    
    dap_pkey_t *l_pkey = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        printf("Command 'delegate' requires parameter -net\n");
        return -1;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_str);
    }
    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_str);
    } else {
        l_port = atoi(l_port_str);
    }

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        printf("Command 'delegate' requires parameter -w\n");
        return -1;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, arg_wallets_path, NULL);
    if (!l_wallet) {
        printf("Specified wallet not found\n");
        return -2;
    }
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    dap_chain_addr_t l_signing_addr, l_sovereign_addr = {};
    uint256_t l_sovereign_tax = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pkey_full", &l_pkey_full_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-sign_type", &l_sign_type_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
    if (!l_cert_str && !l_order_hash_str && !l_pkey_full_str) {
        printf("Command 'delegate' requires parameter -cert and/or -order and/or -pkey\n");
        dap_enc_key_delete(l_enc_key);
        return -1;
    }
    if (l_pkey_full_str) {
        printf("Command 'delegate' requires only one, -pkey or -pkey_full\n");
        dap_enc_key_delete(l_enc_key);
        return -1;
    }
    if (( l_pkey_full_str) && !l_sign_type_str) {
        printf("Command 'delegate' requires parameter -sign_type for pkey\n");
        dap_enc_key_delete(l_enc_key);
        return -1;
    }
    uint256_t l_value = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        if (!l_order_hash_str) {
            printf("Command 'delegate' requires parameter -value\n");
            dap_enc_key_delete(l_enc_key);
            return -1;
        }
    } else {
        l_value = dap_chain_balance_scan(l_value_str);
        if (IS_ZERO_256(l_value)) {
            printf("Unrecognized number in '-value' param\n");
            dap_enc_key_delete(l_enc_key);
            return -1;
        }
    }
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    if (l_cert_str) {
        dap_cert_t *l_signing_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_signing_cert) {
            printf("Specified certificate not found\n");
            dap_enc_key_delete(l_enc_key);
            return -3;
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, s_get_net_id(l_net_str))) {
            printf("Specified certificate is wrong\n");
            dap_enc_key_delete(l_enc_key);
            return -4;
        }
        l_pkey = dap_pkey_from_enc_key(l_signing_cert->enc_key);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-node_addr", &l_node_addr_str);
    }  else if (l_pkey_full_str) {
        dap_sign_type_t l_type = dap_sign_type_from_str(l_sign_type_str);
        if (l_type.type == SIG_TYPE_NULL) {
            printf("Wrong sign type\n");
            dap_enc_key_delete(l_enc_key);
            return -5;
        }
        l_pkey = dap_pkey_get_from_str(l_pkey_full_str);
        if (!l_pkey) {
            printf("Invalid pkey string format, can't get pkey_full\n");
            dap_enc_key_delete(l_enc_key);
            return -6;
        }
        if (l_pkey->header.type.type != dap_pkey_type_from_sign_type(l_type).type) {
            printf("pkey and sign types is different\n");
            dap_enc_key_delete(l_enc_key);
            return -6;
        }
        dap_chain_hash_fast_t l_hash_public_key = {0};
        if (!dap_pkey_get_hash(l_pkey, &l_hash_public_key)) {
            printf("Invalid pkey hash format\n");
            dap_enc_key_delete(l_enc_key);
            return -6;
        }
        dap_chain_addr_fill(&l_signing_addr, l_type, &l_hash_public_key, s_get_net_id(l_net_str));
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-node_addr", &l_node_addr_str);
    }

    dap_chain_node_addr_t l_node_addr = g_node_addr;
    if (l_node_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_addr, l_node_addr_str)) {
            printf("Unrecognized node addr %s\n", l_node_addr_str);
            dap_enc_key_delete(l_enc_key);
            return -7;
        }
    }
    if (l_order_hash_str) {
        uint256_t l_tax;
        uint256_t l_value_max;
        int l_prev_tx_count = 0;
        dap_chain_net_srv_order_t* l_order = dap_get_remote_srv_order(l_net_str, l_order_hash_str, &l_tax, &l_value_max, &l_sovereign_addr, &l_sovereign_tax, l_url_str, l_port);
        if (!l_order) {
            printf("Error: Failed to get order from remote node\n");
            dap_enc_key_delete(l_enc_key);
            return -8;
        }
        l_sovereign_tax = l_tax;

        if (l_order->direction == SERV_DIR_BUY) { // Staker order
            if (!l_cert_str) {
                printf("Command 'delegate' requires parameter -cert with this order type\n");
                dap_enc_key_delete(l_enc_key);
                return -1;
            }
            if (l_order->ext_size != 0) {
                printf("Specified order has invalid size\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -9;
            }

            dap_chain_tx_out_cond_t *l_cond_tx = NULL;
            char data[512];
            snprintf(data, sizeof(data), 
                    "{\"method\": \"ledger\",\"params\": [\"ledger;info;-hash;%s;-net;%s\"],\"id\": \"1\"}", 
                    dap_chain_hash_fast_to_str_static(&l_order->tx_cond_hash), l_net_str);
            
            json_object *response = dap_request_command_to_rpc(data, l_net_str, l_url_str, l_port);
            if (!response) {
                printf("Error: Failed to get response from remote node\n");
                return -15;
            }
            
            json_object *items = json_object_object_get(response, "ITEMS");
            if (!items) {
                printf("Error: No items found in response\n");
                return -16;
            }
            int items_count = json_object_array_length(items);
            for (int i = 0; i < items_count; i++) {
                json_object *item = json_object_array_get_idx(items, i);
                const char *item_type = json_object_get_string(json_object_object_get(item, "item type"));
                if (dap_strcmp(item_type, "OUT COND") == 0) {
                    const char *subtype = json_object_get_string(json_object_object_get(item, "subtype"));
                    if (!dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE")) {
                        l_cond_tx = DAP_NEW_Z(dap_chain_tx_out_cond_t);
                        l_cond_tx->header.item_type = TX_ITEM_TYPE_OUT_COND;
                        l_cond_tx->header.value = dap_chain_balance_scan(json_object_get_string(json_object_object_get(item, "value")));
                        l_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
                        l_cond_tx->header.srv_uid.uint64 = strtoull(json_object_get_string(json_object_object_get(item, "uid")), NULL, 16);
                        l_cond_tx->header.ts_expires = dap_time_from_str_rfc822(json_object_get_string(json_object_object_get(item, "ts_expires")));
                        l_cond_tx->subtype.srv_stake_pos_delegate.signing_addr = *dap_chain_addr_from_str(json_object_get_string(json_object_object_get(item, "signing_addr")));
                        if (dap_chain_node_addr_from_str(&l_cond_tx->subtype.srv_stake_pos_delegate.signer_node_addr, json_object_get_string(json_object_object_get(item, "signer_node_addr"))) != 0) {
                            printf("Error: Failed to parse signer node address\n");
                            return -17;
                        }
                        l_cond_tx->tsd_size = json_object_get_int(json_object_object_get(item, "tsd_size"));
                        l_prev_tx_count++;
                        break;
                    }
                } else if (dap_strcmp(item_type, "OUT") == 0 || dap_strcmp(item_type, "OUT COND") == 0 || dap_strcmp(item_type, "OUT OLD") == 0) {
                    l_prev_tx_count++;
                }
            }
            if (!l_cond_tx) {
                printf("Error: No transaction output condition found\n");
                return -7;
            }

            json_object *spent_outs = json_object_object_get(response, "all OUTs yet unspent");
            const char *spent_outs_value = json_object_get_string(spent_outs);
            if (spent_outs_value && dap_strcmp(spent_outs_value, "yes") != 0) {
                printf("Error: Transaction output item already used\n");
                return -9;
            }

            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, s_get_native_ticker(l_net_str));
            const char *l_token_ticker = json_object_get_string(json_object_object_get(response, "token_ticker"));
            if (!l_token_ticker) {
                printf("Error: Token ticker not found in response\n");
                return -18;
            }
            json_object_put(response);
            if (dap_strcmp(l_token_ticker, l_delegated_ticker)) {
                printf("Requested conditional transaction have another ticker (not %s)\n", l_delegated_ticker);
                return -13;
            }
            if (l_cond_tx->tsd_size != dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size(true, 0)) {
                printf("The order's conditional transaction has invalid format\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -14;
            }
            if (compare256(l_cond_tx->header.value, l_order->price)) {
                printf("The order's conditional transaction has different value\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -15;
            }
            if (!dap_chain_addr_is_blank(&l_cond_tx->subtype.srv_stake_pos_delegate.signing_addr) ||
                    l_cond_tx->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
                printf("The order's conditional transaction gas not blank address or key\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -16;
            }
            l_value = l_order->price;
        } else {
            if (!l_value_str) {
                printf("Command 'delegate' requires parameter -value with this order type\n");
                dap_enc_key_delete(l_enc_key);
                return -1;
            }
            const char *l_sovereign_addr_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tax_addr", &l_sovereign_addr_str);
            if (l_sovereign_addr_str) {
                dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_sovereign_addr_str);
                if (!l_spec_addr) {
                    printf("Specified address is ivalid\n");
                    return -17;
                }
                l_sovereign_addr = *l_spec_addr;
                DAP_DELETE(l_spec_addr);
            } else
                dap_chain_addr_fill_from_key(&l_sovereign_addr, l_enc_key, s_get_net_id(l_net_str));

            if (l_order_hash_str && compare256(l_value, l_order->price) == -1) {
                const char *l_coin_min_str, *l_value_min_str =
                    dap_uint256_to_char(l_order->price, &l_coin_min_str);
                printf("Number in '-value' param %s is lower than order minimum allowed value %s(%s)\n",
                                                  l_value_str, l_coin_min_str, l_value_min_str);
                dap_enc_key_delete(l_enc_key);
                return -18;
            }
            if (l_order_hash_str && compare256(l_value, l_value_max) == 1) {
                const char *l_coin_max_str, *l_value_max_str =
                    dap_uint256_to_char(l_value_max, &l_coin_max_str);
                printf("Number in '-value' param %s is higher than order minimum allowed value %s(%s)\n",
                                                  l_value_str, l_coin_max_str, l_value_max_str);
                dap_enc_key_delete(l_enc_key);
                return -19;
            }
            size_t l_sign_size = 0;
            dap_sign_t *l_sign = dap_get_remote_srv_order_sign(l_net_str, l_order_hash_str, l_url_str, l_port);
            if (!l_sign) {
                printf("Specified order is unsigned\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -20;
            }
            dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, s_get_net_id(l_net_str));
            l_pkey = dap_pkey_get_from_sign(l_sign);
            char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, s_get_native_ticker(l_net_str));
            if (dap_strcmp(l_order->price_ticker, l_delegated_ticker_str)) {
                printf("Specified order is invalid\n");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return -21;
            }
            l_node_addr = l_order->node_addr;
        }
        DAP_DELETE(l_order);
        if (compare256(l_sovereign_tax, dap_chain_coins_to_balance("100.0")) == 1 ||
                compare256(l_sovereign_tax, GET_256_FROM_64(100)) == -1) {
            printf("Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%\n");
            dap_enc_key_delete(l_enc_key);
            return -22;
        }
        DIV_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
    }
    if (!l_pkey) {
        printf("pkey not defined\n");
        dap_enc_key_delete(l_enc_key);
        return -6;
    }

    // TODO: need to make sure that the key and node are required verification 
    // int l_check_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
    // if (l_check_result) {
    //     printf("Key and node verification error\n");
    //     dap_enc_key_delete(l_enc_key);
    //     return l_check_result;
    // }
 

    uint256_t l_allowed_min = s_get_key_delegating_min_value(l_net_str, l_url_str, l_port);
    if (compare256(l_value, l_allowed_min) == -1) {
        const char *l_coin_min_str, *l_value_min_str = dap_uint256_to_char(l_allowed_min, &l_coin_min_str);
        printf("Number in '-value' param %s is lower than minimum allowed value %s(%s)\n",
                                          l_value_str, l_coin_min_str, l_value_min_str);
        dap_enc_key_delete(l_enc_key);
        return -23;
    }
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        printf("Command 'delegate' requires parameter -fee\n");
        dap_enc_key_delete(l_enc_key);
        return -1;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        printf("Unrecognized number in '-fee' param\n");
        dap_enc_key_delete(l_enc_key);
        return -1;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_stake_tx_create_compose(l_net_str, l_enc_key, l_value, l_fee, &l_signing_addr, &l_node_addr,
                                                   l_order_hash_str ? &l_sovereign_addr : NULL, l_sovereign_tax, l_prev_tx, l_pkey, l_url_str, l_port);
    dap_enc_key_delete(l_enc_key);
    DAP_DELETE(l_pkey);

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    DAP_DELETE(l_tx);

    return 0;

}

// Freeze staker's funds when delegating a key
dap_chain_datum_tx_t *dap_stake_tx_create_compose(const char * a_net_str, dap_enc_key_t *a_key,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, const char *l_url_str, int l_port)
{
    if  (!a_net_str || !a_key || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr)
        return NULL;
    const char *l_native_ticker = s_get_native_ticker(a_net_str);
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_key, s_get_net_id(a_net_str));
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t * l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_str, &l_net_fee, &l_net_fee_addr, l_url_str, l_port);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);

    dap_list_t *l_list_fee_out = NULL;


    json_object *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_net_str, &l_owner_addr, l_url_str, l_port);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs_delegated = dap_get_remote_tx_outs(l_delegated_ticker, a_net_str, &l_owner_addr, l_url_str, l_port);
    if (!l_outs_delegated) {
        return NULL;
    }

    int l_out_native_count = json_object_array_length(l_outs_native);
    int l_out_delegated_count = json_object_array_length(l_outs_delegated);

    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                    l_fee_total, 
                                                    &l_fee_transfer);
    if (!l_list_fee_out) {
        printf("Not enough funds to pay fee");
        json_object_put(l_outs_native);
        json_object_put(l_outs_delegated);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    if (!a_prev_tx) {
        dap_list_t * l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_value, 
                                                               &l_value_transfer);
        if (!l_list_used_out) {
            printf("Not enough funds to pay fee");
            json_object_put(l_outs_native);
            json_object_put(l_outs_delegated);
            return NULL;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            printf("Can't compose the transaction input\n");
            goto tx_fail;
        }
    } else {
        dap_hash_fast_t l_prev_tx_hash;
        dap_hash_fast(a_prev_tx, dap_chain_datum_tx_get_size(a_prev_tx), &l_prev_tx_hash);
        int l_out_num = 0;
        dap_chain_datum_tx_out_cond_get(a_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
        // add 'in' item to buy from conditional transaction
        if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_prev_tx_hash, l_out_num, -1)) {
            printf("Can't compose the transaction conditional input\n");
            goto tx_fail;
        }
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        printf("Can't compose the fee transaction input\n");
        goto tx_fail;
    }

    // add 'out_cond' & 'out_ext' items
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr,
                                                                                          a_sovereign_addr, a_sovereign_tax, a_pkey);

    if (!l_tx_out) {
        printf("Can't compose the transaction conditional output\n");
        goto tx_fail;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);
    if (!a_prev_tx) {
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, l_delegated_ticker) != 1) {
                printf("Cant add coin back output\n");
                goto tx_fail;
            }
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            printf("Cant add net fee output\n");
            goto tx_fail;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            printf("Cant add validator fee output\n");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            printf("Cant add fee back output\n");
            goto tx_fail;
        }
    }

    // // add 'sign' item
    // if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key) != 1) {
    //     printf("Can't add sign output\n");
    //     goto tx_fail;
    // }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

static dap_chain_datum_tx_t *dap_order_tx_create_compose(const char * a_net_str, dap_enc_key_t *a_key,
                                               uint256_t a_value, uint256_t a_fee,
                                                uint256_t a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr,
                                                const char *l_url_str, int l_port)
{
    dap_chain_node_addr_t l_node_addr = {};
    return dap_stake_tx_create_compose(a_net_str, a_key, a_value, a_fee,
                             (dap_chain_addr_t *)&c_dap_chain_addr_blank, &l_node_addr,
                             a_sovereign_addr, a_sovereign_tax, NULL, NULL, l_url_str, l_port);
}

//srv_stake order create staker -net <net_name> -w <wallet_with_m_tokens> -value <stake_value> -fee <value> -tax <percent> [-addr <for_tax_collecting>]  [-cert <for_order_signing>] [-H {hex(default) | base58}]
int dap_cli_srv_stake_order_create_staker_compose(int a_argc, char **a_argv) {
    int l_arg_index = 1;
    const char *l_value_str = NULL,
               *l_wallet_str = NULL,
               *l_tax_str = NULL,
               *l_addr_str = NULL,
               *l_fee_str = NULL,
               *l_url_str = NULL,
               *l_port_str = NULL,
               *l_net_str = NULL;
    int l_port = 0;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        printf("Command 'order' requires parameter -net");
        return -1;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-url", &l_url_str)) {
        l_url_str = s_get_net_url(l_net_str);
    }
    if (!dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-port", &l_port_str)) {
        l_port = s_get_net_port(l_net_str);
    } else {
        l_port = atoi(l_port_str);
    }

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        arg_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        arg_wallets_path = dap_strdup(l_wallet_path);
    }

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        printf("Staker order creation requires parameter -value\n");
        return -1;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) { 
        printf("Format -value <256 bit integer>\n");
        return -2;
    }
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        printf("Staker order creation requires parameter -fee\n");
        return -3;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        printf("Format -fee <256 bit integer>\n");
        return -4;
    }
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tax", &l_tax_str);
    if (!l_tax_str) {
        printf("Staker order creation requires parameter -tax\n");
        return -5;
    }
    uint256_t l_tax = dap_chain_coins_to_balance(l_tax_str);
    if (compare256(l_tax, dap_chain_coins_to_balance("100.0")) == 1 ||
            compare256(l_tax, GET_256_FROM_64(100)) == -1) {
        printf("Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%\n");
        return -6;
    }
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        printf("Staker order creation requires parameter -w\n");
        return -7;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallet_path, NULL);
    if (!l_wallet) {
        printf("Specified wallet not found\n");
        return -8;
    }
    // Create conditional transaction for order
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    dap_chain_addr_t l_addr = {};
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
    if (l_addr_str) {
        dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_addr_str);
        if (!l_spec_addr) {
            printf("Specified address is ivalid\n");
            DAP_DELETE(l_enc_key);
            return -9;
        }
        l_addr = *l_spec_addr;
        DAP_DELETE(l_spec_addr);
    } else
        dap_chain_addr_fill_from_key(&l_addr, l_enc_key, s_get_net_id(l_net_str));
    DIV_256(l_tax, GET_256_FROM_64(100), &l_tax);
    dap_chain_datum_tx_t *l_tx = dap_order_tx_create_compose(l_net_str, l_enc_key, l_value, l_fee, l_tax, &l_addr, l_url_str, l_port);
    DAP_DEL_Z(l_enc_key);
    // char *l_tx_hash_str = NULL;
    // if (!l_tx || !(l_tx_hash_str = s_stake_tx_put(l_tx, l_net, a_hash_out_type))) {
    //     printf("Can't compose transaction for order, examine log files for details\n");
    //     DAP_DEL_Z(l_tx);
    //     return -10;
    // }

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    DAP_DELETE(l_tx);
    // Create the order & put it in GDB

    // dap_hash_fast_t l_tx_hash = {};
    // dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
    // char *l_cert_str = NULL;
    // dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", (const char **)&l_cert_str);
    // if (!l_cert_str)
    //     l_cert_str = "node-addr";
    // dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
    // if (!l_cert) {
    //     printf("Can't load cert %s\n", l_cert_str);
    //     DAP_DELETE(l_tx_hash_str);
    //     return -11;
    // }
    // if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
    //     printf("Certificate \"%s\" has no private key\n", l_cert_str);
    //     return -12;
    // }
    // char *l_order_hash_str = s_staker_order_create(l_net, l_value, &l_tx_hash, l_cert->enc_key, a_hash_out_type);
    // if (!l_order_hash_str) {
    //     printf("Can't compose the order\n");
    //     DAP_DELETE(l_tx_hash_str);
    //     return -13;
    // }
    // json_object * l_json_obj_create_val = json_object_new_object();
    // json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
    // if (dap_strcmp(l_sign_str, ""))
    //     json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
    // json_object_object_add(l_json_obj_create_val, "order_hash", json_object_new_string(l_order_hash_str));
    // json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
    // json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
    // DAP_DELETE(l_order_hash_str);
    // DAP_DELETE(l_tx_hash_str);
}

// srv_xchange purchase -order <order hash> -net <net_name> -w <wallet_name> -value <value> -fee <value>
// int dap_tx_create_xchange_purchase_compose(int argc, char ** argv) {
//     int arg_index = 1;
//     const char * l_net_name = NULL;
//     const char * l_wallet_name = NULL;  
//     const char * l_order_hash = NULL;
//     const char * l_value = NULL;
//     const char * l_fee = NULL;

//     dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
//     if (!l_net_name) {
//         printf("tx_create requires parameter '-net'");
//         return -1;
//     }

//     dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_name);
//     if (!l_wallet_name) {
//         printf("Error: Command 'purchase' requires parameter -w\n");
//         return -1;
//     }
//     dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, arg_wallets_path, NULL);
//     if (!l_wallet) {
//         printf("Error: Specified wallet not found\n");
//         return -2;
//     }
//     dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-order", &l_order_hash);
//     if (!l_order_hash) {
//         printf("Error: Command 'purchase' requires parameter -order\n");
//         return -3;
//     }
//     dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &l_value);
//     if (!l_value) {
//         printf("Error: Command 'purchase' requires parameter -value\n");
//         return -4;
//     }
//     uint256_t l_datoshi_buy = dap_chain_balance_scan(l_value);
//     dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &l_fee);
//     if (!l_fee) {
//         printf("Error: Command 'purchase' requires parameter -fee\n");
//         return -5;
//     }
//     uint256_t l_datoshi_fee = dap_chain_balance_scan(l_fee);
//     dap_hash_fast_t l_tx_hash = {};
//     dap_chain_hash_fast_from_str(l_order_hash, &l_tx_hash);
//     char *l_str_ret_hash = NULL;
//     int l_ret_code = dap_chain_net_srv_xchange_purchase_compose(l_net_name, &l_tx_hash, l_datoshi_buy, l_datoshi_fee,
//                                                         l_wallet, &l_str_ret_hash);
//     switch (l_ret_code) {
//         case XCHANGE_PURCHASE_ERROR_OK: {
//             printf("Exchange transaction has done\n");
//             printf("hash: %s\n", l_str_ret_hash);
//             DAP_DELETE(l_str_ret_hash);
//             return 0;
//         }
//         case XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND: {
//             printf("Error: Specified order not found\n");
//             return -6;
//         }
//         case XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE: {
//             printf("Error: Can't create price from order\n");
//             return -7;
//         }
//         case XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX: {
//             printf("Error: Exchange transaction error\n");
//             return -8;
//         }
//         default: {
//             printf("Error: An error occurred with an unknown code: %d.\n", l_ret_code);
//             return -9;
//         }
//     }
//     return 0;
// }


// dap_chain_net_srv_xchange_purchase_error_t dap_chain_net_srv_xchange_purchase_compose(const char *a_net_name, dap_hash_fast_t *a_order_hash, uint256_t a_value,
//                                        uint256_t a_fee, dap_chain_wallet_t *a_wallet, char **a_hash_out){
//     if (!a_net_name || !a_order_hash || !a_wallet || !a_hash_out) {
//         return XCHANGE_PURCHASE_ERROR_INVALID_ARGUMENT;
//     }
//     dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_order_hash);
//     if (l_cond_tx) {
//         dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(a_net, l_cond_tx, a_order_hash, &a_fee, false);
//         if(!l_price){
//             return XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE;
//         }
//         // Create conditional transaction
//         char *l_ret = NULL;
//         dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, a_wallet, a_value, a_fee);
//         if (l_tx ) {
//             l_ret = s_xchange_tx_put(l_tx, a_net);
//         }
//         DAP_DELETE(l_price);
//         if (l_tx && l_ret){
//             *a_hash_out = l_ret;
//             return XCHANGE_PURCHASE_ERROR_OK;
//         } else
//             return XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX;
//     } else {
//         return XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND;
//     }
// }


