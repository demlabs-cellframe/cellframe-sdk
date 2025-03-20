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

#include <curl/curl.h>


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

void bad_option(){
    printf("Usage: %s {{-w, --wallet <path_to_wallet_file> | -z, --seed <seed_phrase> -s <sign_type>} [OPTIONS] | {-c -w <wallet_name> -d <path_to_save_wallet_file> -s <sign_type> -z <seed_phrase>} | {-a {-w <path_to_wallet_file> | -z, --seed <seed_phrase> -s <sign_type>} -i 0x<net_id>}} \n\r \
    stake_lock hold -net <net_name> -w <wallet_name> -time_staking <YYMMDD> -token <ticker> -value <value> -fee <value> -chain_id <chain_id>  [-reinvest <percentage>] \n\r \
    stake_lock take -net <net_name> -w <wallet_name> -tx <transaction_hash> -fee <value> -chain_id <chain_id> \
    \t\tstake_lock command doesn't support old stake command",

    dap_get_appname());
    exit(EXIT_FAILURE);
}


size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    char **response = (char **)userdata;
    *response = realloc(*response, total_size + 1);
    if (*response == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    memcpy(*response, ptr, total_size);
    (*response)[total_size] = '\0';
    return total_size;
}

json_object* request_command_to_rpc_by_curl(const char * request){
    CURL *curl;
    CURLcode res;
    char *response = NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    json_object * result = NULL;

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, RPC_NODES_URL);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            json_object *json = json_tokener_parse(response);
            if (json == NULL) {
                fprintf(stderr, "Failed to parse JSON response\n");
            } else {
                if (!json_object_object_get_ex(json, "result", &result)) {
                    fprintf(stderr, "Result field not found in JSON response\n");
                } else {
                    json_object_get(result);
                }
                json_object_put(json);
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(response);
    }

    curl_global_cleanup();
    return result;
}

struct options {
    char *cmd;
    char *subcmd[5];
    int count_of_subcommands;
    int (*handler) (int argc, char **argv);
} s_opts[] = {
{ "tx_create", {"compose"}, 1, dap_tx_create_compose },
{ "xchange_create", {"compose"}, 1, dap_tx_create_xchange_compose },
{ "tx_cond_create", {"compose"}, 1, dap_tx_cond_create_compose },
{ "stake_lock", {"hold"}, 1, dap_cli_hold_compose },
{ "stake_lock", {"take"}, 1, dap_cli_take_compose },
{ "voting", {"create"}, 1, dap_cli_voting_compose }
};
/*
int main(int argc, char **argv)
{
    int l_argv_start = 1, l_argvi, l_err = -2, l_ret_cmd = -1;
    dap_set_appname("cellframe-tool-compose");

    if (argc == 1){
        bad_option();
    }

    const char *l_wallet_path = NULL;
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-wallet_path", &l_wallet_path);
    if (!l_wallet_path) {
        c_wallets_path =
        #ifdef DAP_OS_WINDOWS
                    dap_strdup_printf("%s/var/lib/wallets", regGetUsrPath());
        #elif defined DAP_OS_MAC
                    dap_strdup_printf("Library/Application Support/CellframeNode/var/lib/wallets");
        #elif defined DAP_OS_UNIX
                    dap_strdup_printf("/opt/CellframeNode/var/lib/wallets");
        #endif
    } else {
        c_wallets_path = dap_strdup(l_wallet_path);
    }

    size_t i, l_size = sizeof(s_opts) / sizeof(struct options);
    for (i = 0; i < l_size; ++i) {
        l_argvi = l_argv_start;
        if (argc >= l_argvi && !strncmp(s_opts[i].cmd, argv[l_argvi], strlen (argv[l_argvi]) + 1)) {
            l_err = 0;
            for (int isub = 0; isub < s_opts[i].count_of_subcommands; isub++) {
                if ( argc - 1 < ++l_argvi || strncmp(s_opts[i].subcmd[isub], argv[l_argvi], strlen(argv[l_argvi]) + 1) ) {
                    l_err = -1;
                    break;
                }
            }
            if ( !l_err ) {
                l_ret_cmd = s_opts[i].handler(argc, argv);
                break;
            }
        }
    }
    switch ( l_err ) {
    case -2:
        printf("Command \"%s\" not found.\n", argv[1]);
        bad_option();
        break;
    case -1:
        printf("No subcommand was found for command \"%s\".\n", argv[1]);
        bad_option();
        break;
    default: break;
    }
    return l_err ? l_err : l_ret_cmd;
}
*/
int dap_tx_create_xchange_compose(int argc, char ** argv) {
    int arg_index = 1;
    const char *l_net_name = NULL;
    const char *l_token_sell = NULL;
    const char *l_token_buy = NULL;
    const char *l_wallet_name = NULL;
    const char *l_value_str = NULL;
    const char *l_rate_str = NULL;
    const char *l_fee_str = NULL;

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token_sell", &l_token_sell);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token_buy", &l_token_buy);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &l_value_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-rate", &l_rate_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &l_fee_str);

    if (!l_net_name) {
        printf("xchange_create requires parameter '-net'");
        return -1;
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

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
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
                                     l_token_sell, l_value, l_rate, l_fee, l_wallet);
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
    const char * l_emission_chain_name = NULL;
    const char * l_tx_num_str = NULL;
    const char *l_emission_hash_str = NULL;
    const char *l_cert_str = NULL;
    dap_cert_t *l_cert = NULL;
    dap_enc_key_t *l_priv_key = NULL;
    dap_chain_hash_fast_t l_emission_hash = {};
    size_t l_tx_num = 0;
    dap_chain_wallet_t * l_wallet_fee = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        printf("Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    if (!l_net_name) {
        printf("tx_create requires parameter '-net'");
        return -1;
    }

    uint256_t *l_value = NULL;
    uint256_t l_value_fee = {};
    dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from_wallet", &l_from_wallet_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-wallet_fee", &l_wallet_fee_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-tx_num", &l_tx_num_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);

    if(l_tx_num_str)
        l_tx_num = strtoul(l_tx_num_str, NULL, 10);

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
    if (!addr_base58_to) {
        printf("tx_create requires parameter '-to_addr'");
        return -5;
    }
    if (!str_tmp) {
        printf("tx_create requires parameter '-value' to be valid uint256 value");
        return -6;
    }
    l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
    l_value_el_count = dap_str_symbol_count(str_tmp, ',') + 1;

    if (l_addr_el_count != l_value_el_count) {
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
    
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, c_wallets_path, NULL);
    if(!l_wallet) {
        printf("Can't open wallet %s", l_from_wallet_name);
        return -12;
    }


    dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet, s_get_net_id(l_net_name));
    for (size_t i = 0; i < l_addr_el_count; ++i) {
        if (dap_chain_addr_compare(l_addr_to[i], l_addr_from)) {
            printf("The transaction cannot be directed to the same address as the source.");
            for (size_t j = 0; j < l_addr_el_count; ++j) {
                    DAP_DELETE(l_addr_to[j]);
            }
            DAP_DEL_MULTY(l_addr_to, l_value);
            return -13;
        }
    }



    l_priv_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create_compose(l_net_name, l_addr_from, l_addr_to, l_token_ticker, l_value, l_value_fee, l_addr_el_count);

    json_object * l_json_obj_ret = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_json_obj_ret);
    printf("%s", json_object_to_json_string(l_json_obj_ret));
    json_object_put(l_json_obj_ret);
    dap_chain_datum_tx_delete(l_tx);
    DAP_DEL_MULTY(l_addr_to, l_value, l_addr_from);
    return 0;
}

bool dap_get_remote_net_fee_and_address(const char *l_net_name, uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee) {
    char data[512];
    snprintf(data, sizeof(data), "{\"method\": \"net\",\"params\": [\"net;get;fee;-net;%s\"],\"id\": \"1\"}", l_net_name);
    json_object *l_json_get_fee = request_command_to_rpc_by_curl(data);
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

bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker, const char *l_net_name, json_object **l_outs, int *l_outputs_count) {
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"wallet\",\"params\": [\"wallet;outputs;-addr;%s;-token;%s;-net;%s\"],\"id\": \"1\"}", 
            dap_chain_addr_to_str(a_addr_from), a_token_ticker, l_net_name);
    json_object *l_json_outs = request_command_to_rpc_by_curl(data);
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
    json_object_put(l_json_outs); // Clean up the JSON object
    return true;
}


dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(const char * l_net_name, dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char* a_token_ticker,
        uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num)
{
    if (!a_addr_from || !a_token_ticker || !a_value || !a_tx_num) {
        return NULL;
    }

    if (dap_chain_addr_check_sum(a_addr_from)) {
        return NULL;
    }

    for (size_t i = 0; i < a_tx_num; ++i) {
        if (!a_addr_to || !a_addr_to[i]) {
            return NULL;
        }
        if (dap_chain_addr_check_sum(a_addr_to[i])) {
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
    if (!dap_get_remote_net_fee_and_address(l_net_name, &l_net_fee, &l_addr_fee)) {
        return NULL;
    }

    bool l_net_fee_used = !IS_ZERO_256(l_net_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(a_addr_from, a_token_ticker, l_net_name, &l_outs, &l_outputs_count)) {
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
            if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to[i], a_value[i]) == 1) {
                SUM_256_256(l_value_pack, a_value[i], &l_value_pack);
            } else {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
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
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
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
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet){
    if (!a_net_name || !a_token_buy || !a_token_sell || !a_wallet) {
        return NULL; // XCHANGE_CREATE_ERROR_INVALID_ARGUMENT
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
    json_object *l_json_coins = request_command_to_rpc_by_curl(data);
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
    json_object *l_json_outs = request_command_to_rpc_by_curl(data);
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
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet, s_get_native_ticker(a_net_name), a_net_name);
    return l_tx;
}

json_object *get_tx_outs_by_curl(const char *a_token_ticker, const char *a_net_name,  dap_chain_addr_t * a_addr) { 
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"wallet\",\"params\": [\"wallet;outputs;-addr;%s;-token;%s;-net;%s\"],\"id\": \"1\"}", 
            dap_chain_addr_to_str(a_addr), a_token_ticker, a_net_name);
    json_object *l_json_outs = request_command_to_rpc_by_curl(data);
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


static dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet,
                                                                 const char *a_native_ticker, const char *a_net_name)
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

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_net_fee);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, s_get_net_id(a_net_name));
    dap_chain_addr_t l_seller_addr = *l_wallet_addr;
    json_object *l_outs_native = get_tx_outs_by_curl(a_native_ticker, a_net_name, l_wallet_addr);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = get_tx_outs_by_curl(a_price->token_sell, a_net_name, l_wallet_addr);
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

    // dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    // // add 'sign' item
    // if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
    //     dap_chain_datum_tx_delete(l_tx);
    //     dap_enc_key_delete(l_seller_key);
    //     printf("Can't add sign output\n");
    //     return NULL;
    // }
    // dap_enc_key_delete(l_seller_key);
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
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        printf("Invalid parameter -H, valid values: -H <hex | base58>\n");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-value", &l_value_datoshi_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &l_value_fee_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-unit", &l_unit_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

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

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path, NULL);
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
                                                        l_srv_uid, l_value_fee, NULL, 0, l_hash_out_type);
    
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
        size_t a_cond_size, const char *a_hash_out_type)
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
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee);
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
    if (!dap_get_remote_wallet_outs_and_count(&l_addr_from, a_token_ticker, a_net_name, &l_outs, &l_outputs_count)) {
        return NULL;
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    json_object_put(l_outs);


    // dap_list_t *l_list_used_out = NULL;
    // if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_token_ticker, &l_addr_from, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
    //     l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
    //                                         &l_addr_from, l_value_need, &l_value_transfer);
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

    // // add 'sign' items
    // if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
    //     dap_chain_datum_tx_delete(l_tx);
    //     printf("Can't add sign output\n");
    //     return NULL;
    // }
    // size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    // dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );
    // dap_chain_datum_tx_delete(l_tx);
    // dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    // char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    // DAP_DELETE(l_datum);

    return l_tx;
}

// stake_lock hold -net <net_name> -w <wallet_name> -time_staking <YYMMDD> -token <ticker> -value <value> -fee <value>[-chain <chain_name>] [-reinvest <percentage>]
int  dap_cli_hold_compose(int a_argc, char **a_argv)
{
    int arg_index = 1;
    const char *l_net_name = NULL, *l_ticker_str = NULL, *l_coins_str = NULL,
            *l_wallet_str = NULL, *l_cert_str = NULL, *l_chain_id_str = NULL,
            *l_time_staking_str = NULL, *l_reinvest_percent_str = NULL, *l_value_fee_str = NULL;

    const char *l_wallets_path								=	c_wallets_path;
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value;
    dap_enc_key_t						*l_key_from;
    dap_chain_wallet_t					*l_wallet;
    dap_chain_addr_t					*l_addr_holder;


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

    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"ledger\",\"params\": [\"ledger;list;coins;-net;%s\"],\"id\": \"2\"}", l_net_name);
    json_object *l_json_coins = request_command_to_rpc_by_curl(data);
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

    json_object *l_json_outs = request_command_to_rpc_by_curl(data);
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
                                                           l_delegated_ticker_str, l_value_delegated, l_chain_id_str);

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
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value, const char * l_chain_id_str)
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
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);

    json_object *l_outs_native = get_tx_outs_by_curl(l_native_ticker, a_net_name, &l_addr);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs_main = NULL;
    if (!dap_strcmp(a_main_ticker, l_native_ticker)) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = get_tx_outs_by_curl(a_main_ticker, a_net_name, &l_addr);
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
    // // add 'sign' item
    // if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
    //     dap_chain_datum_tx_delete(l_tx);
    //     printf("Error: Can't add sign output\n");
    //     return NULL;
    // }

    // size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    // dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );

    // return l_datum;
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
    
    json_object *response = request_command_to_rpc_by_curl(data);
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

    if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path, NULL))) {
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
                                          l_delegated_ticker_str, l_value_delegated);

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
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value)
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

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_name, &l_net_fee, &l_addr_fee);

    json_object *l_outs_native = get_tx_outs_by_curl(l_native_ticker, a_net_name, &l_addr);
    if (!l_outs_native) {
        return NULL;
    }

    json_object *l_outs_delegated = get_tx_outs_by_curl(a_delegated_ticker_str, a_net_name, &l_addr);
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
uint256_t s_get_key_delegating_min_value(const char *a_net_str){
    uint256_t l_key_delegating_min_value = uint256_0;
    char data[512];
    snprintf(data, sizeof(data), 
            "{\"method\": \"srv_stake\",\"params\": [\"srv_stake;list;keys;-net;%s\"],\"id\": \"1\"}", 
            a_net_str);
    
    json_object *response = request_command_to_rpc_by_curl(data);
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
    
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        printf("Voting requires parameter '-net' to be valid.\n");
        return -DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING;
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
    dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, c_wallets_path,NULL);
    if (!l_wallet_fee) {
        printf("Wallet %s does not exist\n", l_wallet_str);
        return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST;
    }

    dap_chain_datum_tx_t* l_tx = dap_chain_net_vote_create_compose(l_question_str, l_options_list, l_time_expire, l_max_count, l_value_fee, l_is_delegated_key, l_is_vote_changing_allowed, l_wallet_fee, l_net_str);
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
                              const char *a_net_str) {

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
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(a_net_str, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    json_object *l_outs = NULL;
    int l_outputs_count = 0;
    if (!dap_get_remote_wallet_outs_and_count(l_addr_from, l_native_ticker, a_net_str, &l_outs, &l_outputs_count)) {
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

