/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#pragma once

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_chain_node_cli.h"
#include "json.h"

typedef enum s_com_tx_history_err{
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,

    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_com_tx_history_err_t;

typedef enum cmd_find_list_err {
    DAP_CHAIN_NODE_CLI_FIND_OK = 0,
    DAP_CHAIN_NODE_CLI_FIND_ERR_PARSE_HASH = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_FUND_ERR_UNKNOWN_SUBCMD,
    DAP_CHAIN_NODE_CLI_FIND_ERR_HASH_IS_NOT_SPECIFIED,
    DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_SUBTYPE_DECREE,
    DAP_CHIAN_NODE_CLI_FIND_ERR_SUBTYPE_DECREE_IS_NOT_SPECIFIED,
    DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_PARAMETR_WHERE,
}cmd_find_list_err_t;

typedef enum s_com_parse_net_chain_err{
    DAP_CHAIN_NODE_CLI_COM_PARSE_NET_NET_STR_ERR = 100,
    DAP_CHAIN_NODE_CLI_COM_PARSE_NET_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_PARSE_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_PARSE_NET_CHAIN_PARAM_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_PARSE_NET_UNKNOWN /* MAX */
} s_com_parse_net_chain_err_t;
typedef enum s_com_global_db_json_err {
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK = 0,

    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_COMMAND_ERR,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_OPEN_DIR,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_INIT_DB,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_INIT_SQL,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_COMMIT_TO_DISK,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_PINED,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_UNPINED,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_WRITING_FILED,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_TIME_NO_VALUE,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_KEY_PROVIDED,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_DATA_IN_GROUP,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DELETE_FAILD,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DROP_FAILED,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR,

    
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_REQUIRE_PARAMETER_JSON = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_CAN_NOT_OPEN_JSON_FILE,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_WRONG_JSON_FORMAT,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_REQUIRE_PARAMETER_NET,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_NOT_FOUNT_NET_BY_NAME,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_NOT_FOUNT_CHAIN_BY_NAME,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_NOT_FOUNT_ARRAY_ITEMS,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_INVALID_ITEMS,
    DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL
}s_com_global_db_json_err_t;

typedef enum s_com_tx_wallet_err{
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ACTIVE_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_DEACT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PROTECTION_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CHAIN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_com_tx_wallet_err_t;

/**
 * com_tx_create command
 *
 * Create transaction
 */
typedef enum s_com_tx_create_err{
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_HASH_INVALID = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NET_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE_IS_UINT256,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_WALLET_OR_FROM_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_CHAIN_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_WALLET_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CERT_IS_INVALID,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_CERT_OR_WALLET_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_TOKEN,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_TOKEN_NOT_DECLARATED_IN_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_TO_ADDR,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NOT_FOUND_CHAIN,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NO_PRIVATE_KEY_DEFINED,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_ADD_DATUM_IN_MEMPOOL,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WALLET_DOES_NOT_EXIST,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_SOURCE_ADDRESS_INVALID,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_NETWORK_IS_UNREACHEBLE,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_EQ_SOURCE_DESTINATION_ADDRESS,
    DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT
}s_com_tx_create_err_t;
typedef enum s_com_tx_cond_create{
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_INVALID_PARAMETER_HEX = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_TOKEN,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_W,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_CERT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_VALUE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_UNIT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_SRV_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_SERVICE_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_UNIT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_OPEN_WALLET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CERT_DOES_NOT_CONATIN_VALID_PUBLIC_KEY,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_CONDITIONAL_TX_CREATE
}s_com_tx_cond_create_t;
typedef enum s_com_tx_cond_remove{
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_INVALID_PARAMETER_HEX = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_W,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_HASHES,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_SRV_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_SERVICE_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_OPEN_WALLET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_RECOGNIZE_VALUE_FEE,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NATIVE_TICKER_IN_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_LEDGER_FOR_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_CREATE_NEW_TX,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUESTED_COND_TX_WITH_HASH_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_UNSPENT_COND_TX_IN_HASH_LIST_FOR_WALLET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_SUM_COND_OUTPUTS_MUST_GREATER_THAN_FEES_SUM,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_RETURNING_COINS_OUTPUT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_NETWORK_FEE_OUTPUT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_VALIDATORS_FEE_OUTPUT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_SIGN_OUTPUT,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_FIND_DEFAULT_CHAIN_WITH_TX_FOR_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OTHER_ERROR
}s_com_tx_cond_remove_t;
typedef enum s_com_tx_cond_unspent_find{
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_HEX = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_W,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_SRV_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_SERVICE_UID,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_OPEN_WALLET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NATIVE_TICKER_IN_NET,
    DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_LEDGER_FOR_NET,
}s_com_tx_cond_unspent_find_t;
typedef enum s_com_tx_verify{
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_NET_CHAIN_UNDEFINED,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH,
    DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_TX_NOT_VERIFY
}s_com_tx_verify_t;
typedef enum cmd_mempool_list_err{
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_READ_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CHAIN_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_GET_MEMPOOL_GROUP,
    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_UNKNOWN /* MAX */
} cmd_mempool_list_err_t;


#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_node_cli_cmd_values_parse_net_chain_for_json(json_object* a_json_arr_reply, int *a_arg_index, int a_argc,
                                                           char **a_argv,
                                                           dap_chain_t **a_chain, dap_chain_net_t **a_net,
                                                           dap_chain_type_t a_default_chain_type);


int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index, int a_argc, char **a_argv, void **a_str_reply,
                             dap_chain_t ** a_chain, dap_chain_net_t ** a_net, dap_chain_type_t a_default_chain_type);



/**
 * global_db command
 */
int com_global_db(int a_argc,  char **a_argv, void **a_str_reply, int a_version);
/**
 * Node command
 */
int com_node(int a_argc,  char **a_argv, void **a_str_reply, int a_version);

#ifndef DAP_OS_ANDROID
/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
int com_traceroute(int a_argc,  char** argv, void **a_str_reply, int a_version);

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
int com_tracepath(int a_argc,  char** argv, void **a_str_reply, int a_version);

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
int com_ping(int a_argc,  char** argv, void **a_str_reply, int a_version);
#endif
/**
 * Help command
 */
int com_help(int a_argc,  char **a_argv, void **a_str_reply, int a_version);

int com_version(int a_argc, char **a_argv, void **a_str_reply, int a_version);

/**
 * Token declaration
 */
int com_token_decl(int a_argc,  char **a_argv, void **a_str_reply, int a_version);

int com_token_update(int a_argc, char **a_argv, void **a_str_reply, int a_version);

/**
 * Token declaration add sign
 */
int com_token_decl_sign ( int a_argc,  char **a_argv, void **a_str_reply, int a_version);

/*
 * Token update sign
 */
int com_token_update_sign(int argc, char ** argv, void **a_str_reply, int a_version);

/**
 * Token emission
 */
int com_token_emit (int a_argc,  char **a_argv, void **a_str_reply, int a_version);

/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int a_argc, char **a_argv, void **a_str_reply, int a_version);

int com_tx_create(int a_argc, char **a_argv, void **a_str_reply, int a_version);
int com_mempool_add(int a_argc, char ** a_argv, void **a_json_arr_reply);

int com_tx_create_json(int a_argc, char **a_argv, void **reply, int a_version);
int com_tx_cond_create(int a_argc, char **a_argv, void **reply, int a_version);

typedef enum s_com_token_decl_err{
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FIND_TICKER_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NOT_VALID_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_TOKEN_CANNOT_MATCH,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_CANT_CREATE_DATUM,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_UNKNOWN_TOKEN_TYPE,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FAILED,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NO_SUITABLE_CHAIN
    
}s_com_token_decl_err_t;

typedef enum s_com_token_update_err{
    DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NOT_VALID_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_UNKNOWN_TOKEN_TYPE,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NO_SUITABLE_CHAIN

}s_com_token_update_err_t;

typedef enum s_com_token_decl_sign_err{
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_H_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_UPDATE_UNKNOWN_TOKEN_TYPE,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NOT_VALID_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_HAS_WRONG_SIGNATURE_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_SERT_NOT_VALID_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR

}s_com_token_decl_sign_err_t;

typedef enum s_com_token_emit_err{
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_H_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CERTS,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_ADDR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_CANT_FIND_EMI_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_ADDR_INVALID_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_NOT_VALID_CERT_ERRS,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_NO_SUITABLE_CHAIN

}s_com_token_emit_err_t;

typedef enum s_com_chain_ca_pub_err{
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_FIND_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CORRUPTED_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PLACE_CERT_ERR

}s_com_chain_ca_pub_err_t;

typedef enum s_com_remove_err{
    DAP_CHAIN_NODE_CLI_COM_REMOVE_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_REMOVE_GENERAL_ERR,
    DAP_CHAIN_NODE_CLI_COM_REMOVE_NOTHING_TO_DEL_ERR

}s_com_remove_err_t;

typedef enum s_com_gdb_import_err{
    DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_REQUIRES_PARAMETER_FILENAME,
    DAP_CHAIN_NODE_CLI_COM_GENERAL_ERR,
    DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_CANT_FIND_GDB_PATH_ERR

}s_com_gdb_import_err_t;

typedef enum s_com_stats_err{
    DAP_CHAIN_NODE_CLI_COM_STATS_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_STATS_WRONG_FORMAT_ERR
}s_com_stats_err_t;

typedef enum s_com_print_log_err{
    DAP_CHAIN_NODE_CLI_COM_PRINT_LOG_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_PRINT_LOG_REQUIRES_PARAMETER_AFTER,
    DAP_CHAIN_NODE_CLI_COM_PRINT_LOG_REQUIRES_PARAMETER_LIMIT,
    DAP_CHAIN_NODE_CLI_COM_PRINT_LOG_NO_LOGS
}s_com_print_log_err_t;

int com_tx_cond_remove(int a_argc, char **a_argv, void **reply, int a_version);
int com_tx_cond_unspent_find(int a_argc, char **a_argv, void **reply, int a_version);

/**
 * tx_verify command
 *
 * Verifing transaction
 */

int com_tx_verify(int a_argc, char ** a_argv, void **a_str_reply, int a_version);



char *dap_chain_node_cli_com_tx_history_err(int a_code);

/**
 * tx_history command
 *
 * Transaction history for an address
 */
int com_tx_history(int a_argc, char ** a_argv, void **a_str_reply, int a_version);


// Print log info
int com_print_log(int a_argc, char **a_argv, void **a_str_reply, int a_version);

// Print statistics
int com_stats(int a_argc, char **a_argv, void **a_str_reply, int a_version);

int com_exit(int a_argc, char **a_argv, void **a_str_reply, int a_version);

int cmd_gdb_import(int a_argc, char **a_argv, void **a_str_reply, int a_version);
int cmd_gdb_export(int a_argc, char **a_argv, void **a_str_reply, int a_version);

int com_mempool(int a_argc, char **a_argv, void **a_str_reply, int a_version);
/**
 * Place public CA into the mempool
 */
int com_chain_ca_pub( int a_argc,  char **a_argv, void **a_str_reply, int a_version);
int com_chain_ca_copy( int a_argc,  char **a_argv, void **a_str_reply, int a_version);
int com_signer(int a_argc, char **a_argv, void **a_str_reply, int a_version);
//remove func
int cmd_remove(int a_argc, char **a_argv, void **a_str_reply, int a_version);

/**
 * Handler coomand find
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
int cmd_find(int a_argc, char **a_argv, void **a_str_reply, int a_version);

void dap_notify_new_client_send_info(dap_events_socket_t *a_es, void *a_arg);

int com_exec_cmd(int argc, char **argv, void **reply, int a_version);

/**
 * Policy management
 */
int com_policy(int a_argc, char **a_argv, void **a_str_reply, int a_version);

#ifdef __cplusplus
}
#endif
