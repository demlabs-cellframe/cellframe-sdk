/*
 * Authors:
 * Davlet Sibgatullin <davlet.sibgatullin@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2022
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

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stake_lock.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"

static bool s_debug_more = false;

enum error_code {
    STAKE_NO_ERROR              = 0,
    NET_ARG_ERROR               = 1,
    NET_ERROR                   = 2,
    TOKEN_ARG_ERROR             = 3,
    TOKEN_ERROR                 = 4,
    COINS_ARG_ERROR             = 5,
    COINS_FORMAT_ERROR          = 6,
    ADDR_ARG_ERROR              = 7,
    ADDR_FORMAT_ERROR           = 8,
    CERT_ARG_ERROR              = 9,
    CERT_LOAD_ERROR             = 10,
    CHAIN_ERROR                 = 11,
    CHAIN_EMISSION_ERROR        = 12,
    TIME_ERROR                  = 13,
    NO_MONEY_ERROR              = 14,
    WALLET_ARG_ERROR            = 15,
    WALLET_OPEN_ERROR           = 16,
    CERT_KEY_ERROR              = 17,
    WALLET_ADDR_ERROR           = 18,
    STAKE_ERROR                 = 19,
    TX_ARG_ERROR                = 20,
    HASH_IS_BLANK_ERROR         = 21,
    NO_TX_ERROR                 = 22,
    CREATE_LOCK_TX_ERROR        = 23,
    TX_TICKER_ERROR             = 24,
    NO_DELEGATE_TOKEN_ERROR     = 25,
    NO_VALID_SUBTYPE_ERROR      = 26,
    IS_USED_OUT_ERROR           = 27,
    OWNER_KEY_ERROR             = 28,
    CREATE_TX_ERROR             = 29,
    CREATE_BURNING_TX_ERROR     = 31,
    CREATE_RECEIPT_ERROR        = 32,
    SIGN_ERROR                  = 33,
    CREATE_DATUM_ERROR          = 34,
    ADD_DATUM_BURNING_TX_ERROR  = 35,
    ADD_DATUM_TX_TAKE_ERROR     = 36,
    BASE_TX_CREATE_ERROR        = 37,
    WRONG_PARAM_SIZE            = 38,
    NOT_ENOUGH_TIME             = 39,
    REINVEST_ARG_ERROR          = 40
};

/**
 * @brief The cond_params struct thats placed in tx_cond->params[] section
 */
typedef struct cond_params {
    dap_time_t		time_unlock;
    uint32_t		flags;
    uint8_t			reinvest;
    uint8_t			padding[7];
    dap_hash_fast_t	token_delegated; // Delegate token
    dap_hash_fast_t	pkey_delegated; // Delegate public key
} DAP_ALIGN_PACKED	cond_params_t;

typedef struct dap_chain_ledger_token_emission_for_stake_lock_item {
    dap_chain_hash_fast_t	datum_token_emission_for_stake_lock_hash;
    dap_chain_hash_fast_t	tx_used_out;
//	const char 				datum_token_emission_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
    UT_hash_handle hh;
} dap_chain_ledger_token_emission_for_stake_lock_item_t;

#define LOG_TAG		"dap_chain_net_stake_lock"
#define MONTH_INDEX	8
#define YEAR_INDEX	12

static int s_cli_stake_lock(int a_argc, char** a_argv, char** a_str_reply);
// Verificator callbacks
static void s_callback_decree(dap_chain_net_srv_t* a_srv, dap_chain_net_t* a_net, dap_chain_t* a_chain, dap_chain_datum_decree_t* a_decree, size_t a_decree_size);
dap_chain_ledger_token_emission_for_stake_lock_item_t *s_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash);

/**
 * @brief dap_chain_net_srv_external_stake_init
 * @return
 */
int dap_chain_net_srv_stake_lock_init()
{
    dap_cli_server_cmd_add("stake_lock", s_cli_stake_lock, "Stake lock service commands",
        "stake_lock hold -net <net_name> -wallet <wallet_name> -time_staking <in YYMMDD>\n"
        "\t-token <token_ticker> -coins <value> -reinvest <percentage from 1 to 100 (not necessary)>\n"
        "\t-cert <priv_cert_name> -chain <chain (not necessary)> -chain_emission <chain (not necessary)>\n"
        "stake_lock take -net <net_name> -tx <transaction_hash> -wallet <wallet_name>\n"
        "\t-chain <chain (not necessary)>\n"
    );
    s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);

    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    dap_chain_net_srv_callbacks_t l_srv_callbacks = {};
    l_srv_callbacks.decree = s_callback_decree;

    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "stake_lock", &l_srv_callbacks);
    return 0;
}

/**
 * @brief dap_chain_net_srv_stake_lock_deinit
 */
void dap_chain_net_srv_stake_lock_deinit()
{

}

/**
 * @brief s_callback_decree
 * @param a_srv
 * @param a_net
 * @param a_chain
 * @param a_decree
 * @param a_decree_size
 */
static void s_callback_decree(dap_chain_net_srv_t* a_srv, dap_chain_net_t* a_net, dap_chain_t* a_chain, dap_chain_datum_decree_t* a_decree, size_t a_decree_size)
{

}

/**
 * @brief s_receipt_create
 * @param hash_burning_transaction
 * @param token
 * @param datoshi_burned
 * @return
 */
static dap_chain_datum_tx_receipt_t* s_receipt_create(dap_hash_fast_t* hash_burning_transaction, const char* token, uint256_t datoshi_burned)
{
    uint32_t l_ext_size = sizeof(dap_hash_fast_t) + dap_strlen(token) + 1;
    uint8_t* l_ext = DAP_NEW_STACK_SIZE(uint8_t, l_ext_size);

    memcpy(l_ext, hash_burning_transaction, sizeof(dap_hash_fast_t));
    strcpy((char*)&l_ext[sizeof(dap_hash_fast_t)], token);

    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED };
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    dap_chain_datum_tx_receipt_t* l_receipt = dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, datoshi_burned,
        l_ext, l_ext_size);
    return l_receipt;
}

/**
 * @brief s_cli_hold
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param output_line
 * @return
 */
static enum error_code s_cli_hold(int a_argc, char** a_argv, int a_arg_index, dap_string_t* output_line)
{
    const char *l_net_str, *l_ticker_str, *l_coins_str, *l_wallet_str, *l_cert_str, *l_chain_str, *l_chain_emission_str, *l_time_staking_str, *l_reinvest_percent_str;
    l_net_str = l_ticker_str = l_coins_str = l_wallet_str = l_cert_str = l_chain_str = l_chain_emission_str = l_time_staking_str = l_reinvest_percent_str = NULL;
    const char *l_wallets_path								=	dap_chain_wallet_get_path(g_config);
    char 	delegate_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{[0] = 'm'};
    dap_chain_net_t						*l_net				=	NULL;
    dap_chain_t							*l_chain			=	NULL;
    dap_chain_t							*l_chain_emission	=	NULL;
    dap_chain_net_srv_uid_t				l_uid				=	{ .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    dap_time_t              			l_time_staking		=	0;
    uint8_t								l_reinvest_percent	=	0;
    uint256_t							l_value_delegated	=	{};
    uint256_t 							l_value;
    dap_ledger_t						*l_ledger;
    char								*l_hash_str;
    dap_hash_fast_t						*l_tx_cond_hash;
    dap_hash_fast_t 					*l_base_tx_hash;
    dap_enc_key_t						*l_key_from;
    dap_pkey_t							*l_key_cond;
    dap_chain_wallet_t					*l_wallet;
    dap_chain_addr_t					*l_addr_holder;
    dap_cert_t							*l_cert;
    dap_chain_datum_token_t 			*delegate_token;
    dap_tsd_t							*l_tsd;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;

    dap_string_append_printf(output_line, "---> HOLD <---\n");

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
        || NULL == l_net_str)
        return NET_ARG_ERROR;

    if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
        dap_string_append_printf(output_line, "'%s'", l_net_str);
        return NET_ERROR;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-token", &l_ticker_str)
        || NULL == l_ticker_str
        || dap_strlen(l_ticker_str) > 8) // for 'm' delegated
        return TOKEN_ARG_ERROR;

    l_ledger = l_net->pub.ledger;
    if (NULL == dap_chain_ledger_token_ticker_check(l_ledger, l_ticker_str)) {
        dap_string_append_printf(output_line, "'%s'", l_ticker_str);
        return TOKEN_ERROR;
    }

    strcpy(delegate_ticker_str + 1, l_ticker_str);

    if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(l_ledger, delegate_ticker_str))
    ||	delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL
    ||	!delegate_token->header_native_decl.tsd_total_size
    ||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
        dap_string_append_printf(output_line, "'%s'", delegate_ticker_str);
        return NO_DELEGATE_TOKEN_ERROR;
    }

    l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
    if (strcmp(l_ticker_str, l_tsd_section.ticker_token_from))
        return TOKEN_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-coins", &l_coins_str)
        || NULL == l_coins_str)
        return COINS_ARG_ERROR;

    if (IS_ZERO_256((l_value = dap_chain_balance_scan(l_coins_str))))
        return COINS_FORMAT_ERROR;

    if (!IS_ZERO_256(l_tsd_section.emission_rate)) {
        MULT_256_COIN(l_value, l_tsd_section.emission_rate, &l_value_delegated);
        if (IS_ZERO_256(l_value_delegated))
            return COINS_FORMAT_ERROR;
    } else {
        l_value_delegated = l_value;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str)
        || NULL == l_cert_str)
        return CERT_ARG_ERROR;

    if (NULL == (l_cert = dap_cert_find_by_name(l_cert_str))) {
        dap_string_append_printf(output_line, "'%s'", l_cert_str);
        return CERT_LOAD_ERROR;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
        && l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain)
        return CHAIN_ERROR;

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-chain_emission", &l_chain_emission_str)
        && l_chain_emission_str)
        l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_EMISSION);
    if (!l_chain_emission)
        return CHAIN_EMISSION_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-wallet", &l_wallet_str)
        || NULL == l_wallet_str)
        return WALLET_ARG_ERROR;

    // Read time staking
    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-time_staking", &l_time_staking_str)
        || NULL == l_time_staking_str)
        return TIME_ERROR;

    if (0 == (l_time_staking = dap_time_from_str_simplified(l_time_staking_str))
        || (time_t)(l_time_staking - dap_time_now()) <= 0)
        return TIME_ERROR;

    l_time_staking -= dap_time_now();

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-l_reinvest_percent", &l_reinvest_percent_str)
    &&	NULL != l_reinvest_percent_str) {
        if ((l_reinvest_percent  = atoi(l_reinvest_percent_str)) > 100
        ||	l_reinvest_percent <= 0)
            return REINVEST_ARG_ERROR;
    }

    /*________________________________________________________________________________________________________________*/

    if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path))) {
        dap_string_append_printf(output_line, "'%s'", l_wallet_str);
        return WALLET_OPEN_ERROR;
    }

    if (compare256(dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_ticker_str), l_value) == -1) {
        dap_chain_wallet_close(l_wallet);
        return NO_MONEY_ERROR;
    }

    if (NULL == (l_addr_holder = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id))) {
        dap_chain_wallet_close(l_wallet);
        dap_string_append_printf(output_line, "'%s'", l_wallet_str);
        return WALLET_ADDR_ERROR;
    }

    l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    if (NULL == (l_key_cond = dap_pkey_from_enc_key(l_cert->enc_key))) {
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_addr_holder);
        dap_string_append_printf(output_line, "'%s'", l_cert_str);
        return CERT_KEY_ERROR;
    }

    l_tx_cond_hash = dap_chain_net_srv_stake_lock_mempool_create(l_net, l_key_from, l_key_cond,
                                                                 l_ticker_str, l_value, l_uid,
                                                                 l_addr_holder, l_time_staking, l_reinvest_percent);

    dap_chain_wallet_close(l_wallet);
    DAP_DEL_Z(l_key_cond);

    l_hash_str = (l_tx_cond_hash) ? dap_chain_hash_fast_to_str_new(l_tx_cond_hash) : NULL;

    if (l_hash_str)
        dap_string_append_printf(output_line, "TX STAKE LOCK CREATED\nSuccessfully hash=%s\nSave to take!\n", l_hash_str);
    else {
        DAP_DEL_Z(l_addr_holder);
        return CREATE_LOCK_TX_ERROR;
    }

    DAP_DEL_Z(l_hash_str);

    l_base_tx_hash = dap_chain_mempool_base_tx_create(l_chain_emission, l_tx_cond_hash, l_chain_emission->id,
                                                      l_value_delegated, delegate_ticker_str, l_addr_holder,
                                                      &l_cert, 1);


    l_hash_str = (l_base_tx_hash) ? dap_chain_hash_fast_to_str_new(l_base_tx_hash) : NULL;

    if (l_hash_str)
        dap_string_append_printf(output_line, "BASE_TX_DATUM_HASH=%s\n", l_hash_str);
    else {
        DAP_DEL_Z(l_addr_holder);
        DAP_DEL_Z(l_tx_cond_hash);
        return BASE_TX_CREATE_ERROR;
    }

    DAP_DEL_Z(l_addr_holder);
    DAP_DEL_Z(l_tx_cond_hash);
    DAP_DEL_Z(l_base_tx_hash);
    DAP_DEL_Z(l_hash_str);

    return STAKE_NO_ERROR;
}

static enum error_code s_cli_take(int a_argc, char** a_argv, int a_arg_index, dap_string_t* output_line)
{
    const char *l_net_str, *l_ticker_str, *l_wallet_str, *l_tx_str, *l_tx_burning_str, *l_chain_str;
    l_net_str = l_ticker_str = l_wallet_str = l_tx_str = l_tx_burning_str = l_chain_str = NULL;
    dap_chain_net_t* l_net = NULL;
    const char* l_wallets_path = dap_chain_wallet_get_path(g_config);
    char 	delegate_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{[0] = 'm'};
    int									l_prev_cond_idx     =   0;
    uint256_t							l_value_delegated	= 	{};
    cond_params_t                       *l_params;
    char                                *l_datum_hash_str;
    dap_ledger_t                        *l_ledger;
    dap_chain_wallet_t                  *l_wallet;
    dap_hash_fast_t						l_tx_hash;
    dap_hash_fast_t 					l_tx_burning_hash;
    dap_chain_datum_t                   *l_datum_burning_tx;
    dap_chain_datum_tx_receipt_t        *l_receipt;
    dap_chain_datum_tx_t                *l_tx;
    dap_chain_datum_tx_t                *l_cond_tx;
    dap_chain_tx_out_cond_t             *l_tx_out_cond;
    dap_chain_addr_t                    *l_owner_addr;
    dap_enc_key_t                       *l_owner_key;
    size_t								l_tx_size;
    dap_chain_datum_t                   *l_datum;
    dap_chain_t                         *l_chain;
    dap_chain_datum_token_t				*delegate_token;
    dap_tsd_t							*l_tsd;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;

    dap_string_append_printf(output_line, "---> TAKE <---\n");

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
        || NULL == l_net_str)
        return NET_ARG_ERROR;

    if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
        dap_string_append_printf(output_line, "'%s'", l_net_str);
        return NET_ERROR;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
        && l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain)
        return CHAIN_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_str)
        || NULL == l_tx_str)
        return TX_ARG_ERROR;

    dap_chain_hash_fast_from_hex_str(l_tx_str, &l_tx_hash);

    if (dap_hash_fast_is_blank(&l_tx_hash))
        return HASH_IS_BLANK_ERROR;

    l_ledger = l_net->pub.ledger;

    if (NULL == (l_ticker_str = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash)))
        return TX_TICKER_ERROR;


    strcpy(delegate_ticker_str  + 1, l_ticker_str);

    if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(l_ledger, delegate_ticker_str))
        ||	delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL
        ||	!delegate_token->header_native_decl.tsd_total_size
        ||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
        dap_string_append_printf(output_line, "'%s'", delegate_ticker_str);
        return NO_DELEGATE_TOKEN_ERROR;
    }

    l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
    if (strcmp(l_ticker_str, l_tsd_section.ticker_token_from)) {
        return TOKEN_ERROR;
    }

    l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &l_tx_hash);

    if (NULL == (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, &l_prev_cond_idx)))
        return NO_TX_ERROR;

    if (l_tx_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK)
        return NO_VALID_SUBTYPE_ERROR;

    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_hash, l_prev_cond_idx)) {
        return IS_USED_OUT_ERROR;
    }

    if (l_tx_out_cond->params_size != sizeof(*l_params))// Wrong params size
        return WRONG_PARAM_SIZE;
    l_params = (cond_params_t*)l_tx_out_cond->params;

    if (l_params->flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME) {
        if (l_params->time_unlock > dap_time_now())
            return NOT_ENOUGH_TIME;
    }

    if (!IS_ZERO_256(l_tsd_section.emission_rate)) {
        MULT_256_COIN(l_tx_out_cond->header.value, l_tsd_section.emission_rate, &l_value_delegated);
        if (IS_ZERO_256(l_value_delegated))
            return COINS_FORMAT_ERROR;
    } else {
        l_value_delegated = l_tx_out_cond->header.value;
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-wallet", &l_wallet_str)
        || NULL == l_wallet_str)
        return WALLET_ARG_ERROR;

    if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path)))
        return WALLET_OPEN_ERROR;

    if (NULL == (l_owner_addr = (dap_chain_addr_t*)dap_chain_wallet_get_addr(l_wallet, l_net->pub.id))) {
        dap_chain_wallet_close(l_wallet);
        return WALLET_ADDR_ERROR;
    }

    if (NULL == (l_owner_key = dap_chain_wallet_get_key(l_wallet, 0))) {
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        return OWNER_KEY_ERROR;
    }

    /*________________________________________________________________________________________________________________*/

        //add tx
    if (NULL == (l_tx = dap_chain_datum_tx_create())) {//malloc
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        return CREATE_TX_ERROR;
    }

    dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tx_hash, l_prev_cond_idx, 0);

    dap_chain_datum_tx_add_out_item(&l_tx, l_owner_addr, l_tx_out_cond->header.value);

    //add burning tx
    if (NULL == (l_datum_burning_tx = dap_chain_burning_tx_create(l_chain, l_owner_key, l_owner_addr, NULL,
        delegate_ticker_str, l_value_delegated))) {//malloc
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        dap_chain_datum_tx_delete(l_tx);
        return CREATE_BURNING_TX_ERROR;
    }

    //get tx hash
    dap_hash_fast(l_datum_burning_tx->data, l_datum_burning_tx->header.data_size, &l_tx_burning_hash);

    if (NULL == (l_receipt = s_receipt_create(&l_tx_burning_hash, delegate_ticker_str, l_value_delegated))) {
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_datum_burning_tx);
        return CREATE_RECEIPT_ERROR;
    }

    dap_chain_datum_tx_add_item(&l_tx, (byte_t*)l_receipt);

    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_datum_burning_tx);
        log_it(L_ERROR, "Can't add sign output");
        return SIGN_ERROR;
    }

    dap_chain_wallet_close(l_wallet);
    DAP_DEL_Z(l_owner_addr);

    // Put the transaction to mempool or directly to chains
    l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    if (NULL == (l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size))) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_datum_burning_tx);
        return CREATE_DATUM_ERROR;
    }

    dap_chain_datum_tx_delete(l_tx);

    if (NULL == (l_datum_hash_str = dap_chain_mempool_datum_add(l_datum_burning_tx, l_chain))) {
        DAP_DEL_Z(l_datum_burning_tx);
        DAP_DEL_Z(l_datum);
        return ADD_DATUM_BURNING_TX_ERROR;
    }

    dap_string_append_printf(output_line, "BURNING_TX_DATUM_HASH=%s\n", l_datum_hash_str);
    DAP_DEL_Z(l_datum_burning_tx);
    DAP_DEL_Z(l_datum_hash_str);

    // Processing will be made according to autoprocess policy
    if (NULL == (l_datum_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain))) {
        DAP_DEL_Z(l_datum);
        return ADD_DATUM_TX_TAKE_ERROR;
    }

    dap_string_append_printf(output_line, "TAKE_TX_DATUM_HASH=%s\n", l_datum_hash_str);

    DAP_DEL_Z(l_datum_hash_str);
    DAP_DEL_Z(l_datum);

    return STAKE_NO_ERROR;
}

/**
 * @brief s_error_handler
 * @param errorCode
 * @param output_line
 */
static void s_error_handler(enum error_code errorCode, dap_string_t* output_line)
{
    dap_string_append_printf(output_line, "ERROR!\n");
    switch (errorCode)
    {
    case NET_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -net");
    } break;

    case NET_ERROR: {
        dap_string_append_printf(output_line, "^^^ network not found");
    } break;

    case TOKEN_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -token");
    } break;

    case TOKEN_ERROR: {
        dap_string_append_printf(output_line, "^^^ token ticker not found");
    } break;

    case COINS_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -coins");
    } break;

    case COINS_FORMAT_ERROR: {
        dap_string_append_printf(output_line, "Format -coins <256 bit integer>");
    } break;

    case ADDR_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -addr_holder");
    } break;

    case ADDR_FORMAT_ERROR: {
        dap_string_append_printf(output_line, "wrong address holder format");
    } break;

    case CERT_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -cert");
    } break;

    case CERT_LOAD_ERROR: {
        dap_string_append_printf(output_line, "^^^ can't load cert");
    } break;

    case CHAIN_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command requires parameter '-chain'.\n"
            "you can set default datum type in chain configuration file");
    } break;

    case CHAIN_EMISSION_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command requires parameter '-chain_emission'.\n"
            "you can set default datum type in chain configuration file");
    } break;

    case TIME_ERROR: {
        dap_string_append_printf(output_line, "stake_ext command requires parameter '-time_staking' in simplified format YYMMDD\n"
                                                                        "Example: \"220610\" == \"10 june 2022 00:00\"");
    } break;

    case NO_MONEY_ERROR: {
        dap_string_append_printf(output_line, "Not enough money");
    } break;

    case WALLET_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -wallet");
    } break;

    case WALLET_OPEN_ERROR: {
        dap_string_append_printf(output_line, "^^^ can't open wallet");
    } break;

    case CERT_KEY_ERROR: {
        dap_string_append_printf(output_line, "^^^ cert doesn't contain a valid public key");
    } break;

    case WALLET_ADDR_ERROR: {
        dap_string_append_printf(output_line, "^^^ failed to get wallet address");
    } break;

    case TX_ARG_ERROR: {
        dap_string_append_printf(output_line, "stake_lock command required parameter -tx");
    } break;

    case HASH_IS_BLANK_ERROR: {
        dap_string_append_printf(output_line, "tx hash is blank");
    } break;

    case NO_TX_ERROR: {
        dap_string_append_printf(output_line, "^^^ could not find transaction");
    } break;

    case STAKE_ERROR: {
        dap_string_append_printf(output_line, "STAKE ERROR");
    } break;

    case NOT_ENOUGH_TIME: {
        dap_string_append_printf(output_line, "Not enough time has passed");
    } break;

    case TX_TICKER_ERROR: {
        dap_string_append_printf(output_line, "ticker not found");
    } break;

    case NO_DELEGATE_TOKEN_ERROR: {
        dap_string_append_printf(output_line, " ^^^ delegated token not found");
    } break;

    case NO_VALID_SUBTYPE_ERROR: {
        dap_string_append_printf(output_line, "wrong subtype for transaction");
    } break;

    case IS_USED_OUT_ERROR: {
        dap_string_append_printf(output_line, "tx hash is used out");
    } break;

    case OWNER_KEY_ERROR: {
        dap_string_append_printf(output_line, "key retrieval error");
    } break;

    case CREATE_TX_ERROR: {
        dap_string_append_printf(output_line, "memory allocation error when creating a transaction");
    } break;

    case CREATE_BURNING_TX_ERROR: {
        dap_string_append_printf(output_line, "failed to create a transaction that burns funds");
    } break;

    case CREATE_RECEIPT_ERROR: {
        dap_string_append_printf(output_line, "failed to create receipt");
    } break;

    case SIGN_ERROR: {
        dap_string_append_printf(output_line, "failed to sign transaction");
    } break;

    case ADD_DATUM_BURNING_TX_ERROR: {
        dap_string_append_printf(output_line, "failed to add datum with burning-transaction to mempool");
    } break;

    case ADD_DATUM_TX_TAKE_ERROR: {
        dap_string_append_printf(output_line, "failed to add datum with take-transaction to mempool");
    } break;

    case BASE_TX_CREATE_ERROR: {
        dap_string_append_printf(output_line, "failed to create the base transaction for emission");
    } break;

    case WRONG_PARAM_SIZE: {
        dap_string_append_printf(output_line, "error while checking conditional transaction parameters");
    } break;

    case CREATE_LOCK_TX_ERROR: {
        dap_string_append_printf(output_line, "error creating transaction");
    } break;

    case CREATE_DATUM_ERROR: {
        dap_string_append_printf(output_line, "error while creating datum from transaction");
    } break;

    case REINVEST_ARG_ERROR: {
        dap_string_append_printf(output_line, "reinvestment is set as a percentage from 1 to 100");
    } break;

    default: {
        dap_string_append_printf(output_line, "STAKE_LOCK: Unrecognized error");
    } break;
    }
}

/**
 * @brief s_cli_stake_lock
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
static int s_cli_stake_lock(int a_argc, char** a_argv, char** a_str_reply)
{
    enum {
        CMD_NONE, CMD_HOLD, CMD_TAKE
    };

    enum error_code	errorCode;
    int				l_arg_index = 1;
    int				l_cmd_num = CMD_NONE;
    dap_string_t* output_line = dap_string_new(NULL);

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "hold", NULL))
        l_cmd_num = CMD_HOLD;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "take", NULL))
        l_cmd_num = CMD_TAKE;

    switch (l_cmd_num) {

    case CMD_HOLD: {
        errorCode = s_cli_hold(a_argc, a_argv, l_arg_index + 1, output_line);
    } break;

    case CMD_TAKE: {
        errorCode = s_cli_take(a_argc, a_argv, l_arg_index + 1, output_line);
    } break;

    default: {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
        dap_string_free(output_line, false);
    } return 1;
    }

    if (STAKE_NO_ERROR != errorCode)
        s_error_handler(errorCode, output_line);
    else
        dap_string_append_printf(output_line, "Contribution successfully made");

    dap_cli_server_cmd_set_reply_text(a_str_reply, output_line->str);
    dap_string_free(output_line, true);

    return 0;
}

/**
 * @brief s_give_month_str_from_month_count
 * @param month_count
 * @return
 */
static const char* s_give_month_str_from_month_count(uint8_t month_count)
{

    switch (month_count)
    {
    case 1: {
        return "Jan";
    }
    case 2: {
        return "Feb";
    }
    case 3: {
        return "Mar";
    }
    case 4: {
        return "Apr";
    }
    case 5: {
        return "May";
    }
    case 6: {
        return "Jun";
    }
    case 7: {
        return "Jul";
    }
    case 8: {
        return "Aug";
    }
    case 9: {
        return "Sep";
    }
    case 10: {
        return "Oct";
    }
    case 11: {
        return "Nov";
    }
    case 12: {
        return "Dec";
    }

    default: {
        return "";
    }
    }
}

/**
 * @brief s_give_month_count_from_time_str
 * @param time
 * @return
 */
static uint8_t s_give_month_count_from_time_str(char* time)
{
    const uint8_t len_month = 3;

    if (!memcmp(&time[MONTH_INDEX], "Jan", len_month))
        return 1;
    else if (!memcmp(&time[MONTH_INDEX], "Feb", len_month))
        return 2;
    else if (!memcmp(&time[MONTH_INDEX], "Mar", len_month))
        return 3;
    else if (!memcmp(&time[MONTH_INDEX], "Apr", len_month))
        return 4;
    else if (!memcmp(&time[MONTH_INDEX], "May", len_month))
        return 5;
    else if (!memcmp(&time[MONTH_INDEX], "Jun", len_month))
        return 6;
    else if (!memcmp(&time[MONTH_INDEX], "Jul", len_month))
        return 7;
    else if (!memcmp(&time[MONTH_INDEX], "Aug", len_month))
        return 8;
    else if (!memcmp(&time[MONTH_INDEX], "Sep", len_month))
        return 9;
    else if (!memcmp(&time[MONTH_INDEX], "Oct", len_month))
        return 10;
    else if (!memcmp(&time[MONTH_INDEX], "Nov", len_month))
        return 11;
    else if (!memcmp(&time[MONTH_INDEX], "Dec", len_month))
        return 12;
    else
        return 0;
}

/**
 * @brief s_update_date_by_using_month_count
 * @param time
 * @param month_count
 * @return
 */
static char* s_update_date_by_using_month_count(char* time, uint8_t month_count)
{
    uint8_t		current_month;
    int			current_year;
    const char* month_str;
    const char* year_str;

    if (!time || !month_count)
        return NULL;
    if ((current_month = s_give_month_count_from_time_str(time)) == 0)
        return NULL;
    if ((current_year = atoi(&time[YEAR_INDEX])) <= 0
        || current_year < 22
        || current_year 												> 99)
        return NULL;


    for (uint8_t i = 0; i < month_count; i++) {
        if (current_month == 12)
        {
            current_month = 1;
            current_year++;
        }
        else
            current_month++;
    }

    month_str = s_give_month_str_from_month_count(current_month);
    year_str = dap_itoa(current_year);

    if (*month_str
        && *year_str
        && dap_strlen(year_str) == 2) {
        memcpy(&time[MONTH_INDEX], month_str, 3);	// 3 == len month in time RFC822 format
        memcpy(&time[YEAR_INDEX], year_str, 2);	// 2 == len year in time RFC822 format
    }
    else
        return NULL;

    return time;
}

/**
 * @brief s_callback_verificator
 * @param a_cond
 * @param a_tx
 * @param a_owner
 * @return
 */
bool s_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner)
{
    dap_chain_datum_tx_t									*burning_tx					= NULL;
    dap_chain_tx_out_t										*burning_transaction_out	= NULL;
    uint256_t												l_value_delegated			= {};
    dap_hash_fast_t											hash_burning_transaction;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t	l_tsd_section;
    dap_tsd_t												*l_tsd;
    cond_params_t 											*l_params;
    dap_chain_datum_tx_receipt_t							*l_receipt;
    dap_chain_tx_out_t										*l_tx_out;
    dap_chain_tx_in_cond_t									*l_tx_in_cond;
    const char												*l_tx_ticker;
    dap_chain_datum_token_t									*delegate_token;

    /*if (!a_owner) TODO: ???
    return false;*/

    if (a_cond->params_size != sizeof(*l_params))// Wrong params size
        return false;
    l_params = (cond_params_t*)a_cond->params;

    if (l_params->flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME) {
        if (l_params->time_unlock > dap_time_now())
            return false;
    }

    l_receipt = (dap_chain_datum_tx_receipt_t *)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_RECEIPT, 0);
    if (!l_receipt)
        return false;

#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    if (l_receipt->receipt_info.srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_LOCK_ID)
        return false;
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
    if (l_receipt->receipt_info.srv_uid.uint128 != DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID)
        return false;
#endif

    char delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    if (l_receipt->exts_size) {
        hash_burning_transaction = *(dap_hash_fast_t*)l_receipt->exts_n_signs;
        strcpy(delegated_ticker, (char *)&l_receipt->exts_n_signs[sizeof(dap_hash_fast_t)]);
    } else {
        return false;
    }

    if (dap_hash_fast_is_blank(&hash_burning_transaction))
        return false;

    l_tx_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_OUT,0);

    if (!l_tx_out)
        return false;

    if (!EQUAL_256(a_cond->header.value, l_tx_out->header.value))
        return false;

    if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(a_ledger, delegated_ticker))
        ||	delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL
        ||	!delegate_token->header_native_decl.tsd_total_size
        ||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
        return false;
    }

    l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);

    if (NULL == (l_tx_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_IN_COND, 0)))
        return false;
    if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
        return false;
    if (NULL == (l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_in_cond->header.tx_prev_hash)))
        return false;
    if (strcmp(l_tx_ticker, l_tsd_section.ticker_token_from))
        return false;
    if (NULL == (l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &hash_burning_transaction)))
        return false;
    if (strcmp(l_tx_ticker, delegated_ticker)) {
        return false;
    }

    burning_tx = dap_chain_ledger_tx_find_by_hash(a_ledger, &hash_burning_transaction);
    burning_transaction_out = (dap_chain_tx_out_t*)dap_chain_datum_tx_item_get(burning_tx, 0, TX_ITEM_TYPE_OUT, 0);

    if (!burning_transaction_out)
        return false;

    if (!dap_hash_fast_is_blank(&burning_transaction_out->addr.data.hash_fast)) {
        if (s_debug_more) {
            const char *addr_srt = dap_chain_hash_fast_to_str_new(&burning_transaction_out->addr.data.hash_fast);
            log_it(L_ERROR, "ADDR from burning NOT BLANK: %s", addr_srt);
            DAP_DEL_Z(addr_srt);
        }
        return false;
    }

    if (!IS_ZERO_256(l_tsd_section.emission_rate)) {
        MULT_256_COIN(l_tx_out->header.value, l_tsd_section.emission_rate, &l_value_delegated);
        if (IS_ZERO_256(l_value_delegated))
            return COINS_FORMAT_ERROR;
    } else
        l_value_delegated = l_tx_out->header.value;

    if (s_debug_more) {
        char *str1 = dap_chain_balance_print(burning_transaction_out->header.value);
        char *str2 = dap_chain_balance_print(l_tx_out->header.value);
        char *str3 = dap_chain_balance_print(l_value_delegated);
        log_it(L_INFO, "burning_value: |%s|",	str1);
        log_it(L_INFO, "hold/take_value: |%s|",	str2);
        log_it(L_INFO, "delegated_value |%s|",	str3);
        DAP_DEL_Z(str1);
        DAP_DEL_Z(str2);
        DAP_DEL_Z(str3);
    }

    if (!EQUAL_256(burning_transaction_out->header.value, l_value_delegated))//MULT
        return false;

    return true;
}

/**
 * @brief s_callback_verificator_added
 * @param a_tx
 * @param a_tx_item
 * @param a_tx_item_idx
 * @return
 */
bool	s_callback_verificator_added(dap_ledger_t * a_ledger,dap_chain_datum_tx_t* a_tx, dap_chain_tx_out_cond_t *a_tx_item)
{
    dap_chain_hash_fast_t* l_key_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    if (!l_key_hash)
        return false;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_hash_fast(a_tx, l_tx_size, l_key_hash);
    if (dap_hash_fast_is_blank(l_key_hash)) {
        DAP_DEL_Z(l_key_hash);
        return false;
    }

    s_emission_for_stake_lock_item_add(a_ledger, l_key_hash);

    DAP_DEL_Z(l_key_hash);

    return true;
}

/**
 * @brief s_mempool_create
 * @param a_net
 * @param a_key_from
 * @param a_key_cond
 * @param a_token_ticker
 * @param a_value
 * @param a_srv_uid
 * @param a_addr_holder
 * @param a_count_months
 * @return
 */
static dap_chain_datum_t* s_mempool_create(dap_chain_net_t* a_net,
    dap_enc_key_t* a_key_from, dap_pkey_t* a_key_cond,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value, dap_chain_net_srv_uid_t a_srv_uid,
    dap_chain_addr_t* a_addr_holder, dap_time_t a_time_staking, uint8_t reinvest)
{
    dap_ledger_t* l_ledger = a_net ? dap_chain_ledger_by_net_name(a_net->pub.name) : NULL;
    // check valid param
    if (!a_net || !l_ledger || !a_key_from || !a_key_cond ||
        !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || IS_ZERO_256(a_value))
        return NULL;

    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
//	uint256_t l_value_need = {};
//	SUM_256_256(a_value, a_value_fee, &l_value_need);
    // where to take coins for service
    dap_chain_addr_t l_addr_from;
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, a_net->pub.id);
    // list of transaction with 'out' items
    dap_list_t* l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
        &l_addr_from, a_value, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Nothing to tranfer (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out_cond' and 'out' items
    {
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_net_srv_stake_lock_create_cond_out(a_key_cond, a_srv_uid, a_value, a_time_staking, reinvest);
        if (l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_tx_out_cond);
            //			DAP_DEL_Z(l_tx_out_cond);
                        // transaction fee
            //			if (!IS_ZERO_256(a_value_fee)) {
                            // TODO add condition with fee for mempool-as-service
            //			}
        }//TODO: else return false;
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
    }

    // add 'sign' items
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't add sign output");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t* l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);

    return l_datum;
}

/**
 * @brief dap_chain_net_srv_stake_lock_create_cond_out
 * @param a_key
 * @param a_srv_uid
 * @param a_value
 * @param a_time_staking
 * @param token
 * @return
 */
dap_chain_tx_out_cond_t* dap_chain_net_srv_stake_lock_create_cond_out(dap_pkey_t* a_key, dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value,
    uint64_t a_time_staking, uint8_t reinvest)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t* l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + sizeof(cond_params_t));
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    l_item->header.srv_uid = a_srv_uid;
    l_item->params_size = sizeof(cond_params_t);
    cond_params_t* l_params = (cond_params_t*)l_item->params;
    l_params->reinvest = reinvest;
    if (a_time_staking) {
        l_params->time_unlock = dap_time_now() + a_time_staking;
        l_params->flags |= DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME;
    }
    if (a_key)
        dap_hash_fast(a_key->pkey, a_key->header.size, &l_params->pkey_delegated);

    return l_item;
}


/**
 * @brief dap_chain_net_srv_stake_lock_mempool_create
 * @param a_net
 * @param a_key_from
 * @param a_key_cond
 * @param a_token_ticker
 * @param a_value
 * @param a_srv_uid
 * @param a_addr_holder
 * @param a_time_staking
 * @return
 */
dap_chain_hash_fast_t* dap_chain_net_srv_stake_lock_mempool_create(dap_chain_net_t* a_net,
    dap_enc_key_t* a_key_from, dap_pkey_t* a_key_cond,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value, dap_chain_net_srv_uid_t a_srv_uid,
    dap_chain_addr_t* a_addr_holder, uint64_t a_time_staking, uint8_t reinvest)
{
    // Make transfer transaction
    dap_chain_datum_t* l_datum = s_mempool_create(a_net, a_key_from, a_key_cond, a_token_ticker, a_value, a_srv_uid,
        a_addr_holder, a_time_staking, reinvest);

    if (!l_datum)
        return NULL;

    dap_chain_datum_tx_t* l_tx = (dap_chain_datum_tx_t*)&(l_datum->data);
    size_t l_tx_size = l_datum->header.data_size;

    dap_chain_hash_fast_t* l_key_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    dap_hash_fast(l_tx, l_tx_size, l_key_hash);

    char* l_key_str = dap_chain_hash_fast_to_str_new(l_key_hash);
    char* l_gdb_group = dap_chain_net_get_gdb_group_mempool_by_chain_type(a_net, CHAIN_TYPE_TX);

    if (dap_global_db_set(l_gdb_group, l_key_str, l_datum, dap_chain_datum_size(l_datum), false, NULL, NULL) == true) {
        log_it(L_NOTICE, "Transaction %s placed in mempool group %s", l_key_str, l_gdb_group);
    }

    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}

dap_chain_datum_t* dap_chain_burning_tx_create(dap_chain_t* a_chain, dap_enc_key_t* a_key_from,
    const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value)
{
    // check valid param
    if (!a_chain | !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
        !dap_chain_addr_check_sum(a_addr_from) || (a_addr_to && !dap_chain_addr_check_sum(a_addr_to)) || IS_ZERO_256(a_value))
        return NULL;

    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    dap_list_t* l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
        a_addr_from, a_value, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Not enough funds to transfer");
        return NULL;
    }
    // create empty transaction
    dap_chain_datum_tx_t* l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out' items
    {
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) == 1) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        }
        // coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t* l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);

    DAP_DELETE(l_tx);

    return l_datum;

    //	dap_hash_fast_t * l_ret = DAP_NEW_Z(dap_hash_fast_t);
    //	dap_hash_fast(l_tx, l_tx_size, l_ret);
    //	DAP_DELETE(l_tx);
    //	char *l_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain);

    //	DAP_DELETE( l_datum );
    //
    //	if (l_hash_str) {
    //		DAP_DELETE(l_hash_str);
    //		return l_ret;
    //	}else{
    //		DAP_DELETE(l_ret);
    //		return NULL;
    //	}
}
