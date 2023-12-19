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

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_srv_stake_lock.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_wallet.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv.h"

static bool s_debug_more = false;

enum error_code {
    STAKE_NO_ERROR 				= 0,
    NET_ARG_ERROR				= 1,
    NET_ERROR					= 2,
    TOKEN_ARG_ERROR 			= 3,
    TOKEN_ERROR					= 4,
    COINS_ARG_ERROR				= 5,
    COINS_FORMAT_ERROR			= 6,
    ADDR_ARG_ERROR				= 7,
    ADDR_FORMAT_ERROR			= 8,
    CERT_ARG_ERROR				= 9,
    CERT_LOAD_ERROR				= 10,
    CHAIN_ERROR					= 11,
    CHAIN_EMISSION_ERROR		= 12,
    TIME_ERROR					= 13,
    NO_MONEY_ERROR				= 14,
    WALLET_ARG_ERROR			= 15,
    WALLET_OPEN_ERROR			= 16,
    CERT_KEY_ERROR				= 17,
    WALLET_ADDR_ERROR			= 18,
    STAKE_ERROR  				= 19,
    TX_ARG_ERROR				= 20,
    HASH_IS_BLANK_ERROR			= 21,
    NO_TX_ERROR					= 22,
    CREATE_LOCK_TX_ERROR		= 23,
    TX_TICKER_ERROR				= 24,
    NO_DELEGATED_TOKEN_ERROR	= 25,
    NO_VALID_SUBTYPE_ERROR		= 26,
    IS_USED_OUT_ERROR			= 27,
    OWNER_KEY_ERROR				= 28,
    CREATE_TX_ERROR				= 29,
    CREATE_BURNING_TX_ERROR		= 31,
    CREATE_RECEIPT_ERROR		= 32,
    SIGN_ERROR					= 33,
    CREATE_DATUM_ERROR			= 34,
    ADD_DATUM_BURNING_TX_ERROR	= 35,
    ADD_DATUM_TX_TAKE_ERROR		= 36,
    BASE_TX_CREATE_ERROR		= 37,
    WRONG_PARAM_SIZE			= 38,
    NOT_ENOUGH_TIME				= 39,
    REINVEST_ARG_ERROR			= 40,
    HASH_TYPE_ARG_ERROR         = 41,
    FEE_ARG_ERROR               = 42,
    FEE_FORMAT_ERROR            = 43,
};

typedef struct dap_ledger_token_emission_for_stake_lock_item {
    dap_chain_hash_fast_t	datum_token_emission_for_stake_lock_hash;
    dap_chain_hash_fast_t	tx_used_out;
//	const char 				datum_token_emission_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
    UT_hash_handle hh;
} dap_ledger_token_emission_for_stake_lock_item_t;

#define LOG_TAG		"dap_chain_net_stake_lock"
#define MONTH_INDEX	8
#define YEAR_INDEX	12

static int s_cli_stake_lock(int a_argc, char **a_argv, char **a_str_reply);

// Create stake lock datum
static dap_chain_datum_t *s_stake_lock_datum_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from,
                                                    const char *a_main_ticker, uint256_t a_value,
                                                    uint256_t a_value_fee,
                                                    dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value);
// Create unlock datum
dap_chain_datum_t *s_stake_unlock_datum_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value);
// Callbacks
static void s_stake_lock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_prev_out_item);
static bool s_stake_lock_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool a_owner);
/**
 * @brief dap_chain_net_srv_external_stake_init
 * @return
 */
int dap_chain_net_srv_stake_lock_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, s_stake_lock_callback_verificator, s_stake_lock_callback_updater);
    dap_cli_server_cmd_add("stake_lock", s_cli_stake_lock, "Stake lock service commands",
       "Command:"
                "stake_lock hold\n"
                "Required parameters:\n"
                "-net <net name> -w <wallet name> -time_staking <in YYMMDD>\n"
                "-token <ticker> -value <value> -fee <value>\n"
                "Optional parameters:\n"
                "-chain <chain> -reinvest <percentage from 1 to 100>\n"
                "Command:"
                "stake_lock take\n"
                "Required parameters:\n"
                "-net <net name> -w <wallet name> -tx <transaction hash> -fee <value>\n"
                "Optional parameters:\n"
                "-chain <chain>\n"
    );
    s_debug_more = dap_config_get_item_bool_default(g_config, "ledger", "debug_more", false);
    return 0;
}

/**
 * @brief dap_chain_net_srv_stake_lock_deinit
 */
void dap_chain_net_srv_stake_lock_deinit()
{

}

/**
 * @brief s_cli_hold
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param output_line
 * @return
 */
static enum error_code s_cli_hold(int a_argc, char **a_argv, int a_arg_index, dap_string_t *output_line)
{
    const char *l_net_str = NULL, *l_ticker_str = NULL, *l_coins_str = NULL,
            *l_wallet_str = NULL, *l_cert_str = NULL, *l_chain_str = NULL,
            *l_time_staking_str = NULL, *l_reinvest_percent_str = NULL, *l_value_fee_str = NULL;

    const char *l_wallets_path								=	dap_chain_wallet_get_path(g_config);
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_chain_net_t						*l_net				=	NULL;
    dap_chain_t							*l_chain			=	NULL;
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value;
    dap_ledger_t						*l_ledger;
    char								*l_hash_str;
    dap_enc_key_t						*l_key_from;
    dap_chain_wallet_t					*l_wallet;
    dap_chain_addr_t					*l_addr_holder;
    dap_chain_datum_token_t 			*l_delegated_token;
    dap_tsd_t							*l_tsd;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section;

    dap_string_append_printf(output_line, "---> HOLD <---\n");

    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type, "base58"))
        return HASH_TYPE_ARG_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
    ||	NULL == l_net_str)
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

    if (NULL == dap_ledger_token_ticker_check(l_ledger, l_ticker_str)) {
        dap_string_append_printf(output_line, "'%s'", l_ticker_str);
        return TOKEN_ERROR;
    }

    if ((!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-coins", &l_coins_str) || NULL == l_coins_str) &&
            (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_coins_str) || NULL == l_coins_str))
        return COINS_ARG_ERROR;

    if (IS_ZERO_256( (l_value = dap_chain_balance_scan(l_coins_str)) ))
        return COINS_FORMAT_ERROR;

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);

    if (NULL == (l_delegated_token = dap_ledger_token_ticker_check(l_ledger, l_delegated_ticker_str))
    ||	(l_delegated_token->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)
    ||	!l_delegated_token->header_native_decl.tsd_total_size
    ||	NULL == (l_tsd = dap_tsd_find(l_delegated_token->data_n_tsd, l_delegated_token->header_native_decl.tsd_total_size,
                                      DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
        dap_string_append_printf(output_line, "'%s'", l_delegated_ticker_str);
        return NO_DELEGATED_TOKEN_ERROR;
    }

    l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
    if (strcmp(l_ticker_str, (char*)l_tsd_section->ticker_token_from))
        return TOKEN_ERROR;

    if (IS_ZERO_256(l_tsd_section->emission_rate))
        return TOKEN_ERROR;

    MULT_256_COIN(l_value, l_tsd_section->emission_rate, &l_value_delegated);
    if (IS_ZERO_256(l_value_delegated))
        return COINS_FORMAT_ERROR;

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
    &&	l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if(!l_chain)
        return CHAIN_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str)
    ||	!l_wallet_str)
        return WALLET_ARG_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_value_fee_str)
    ||	!l_value_fee_str)
        return FEE_ARG_ERROR;

    if (IS_ZERO_256( (l_value_fee = dap_chain_balance_scan(l_value_fee_str)) ))
        return FEE_FORMAT_ERROR;

    // Read time staking
    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-time_staking", &l_time_staking_str)
    ||	!l_time_staking_str)
        return TIME_ERROR;

    if (dap_strlen(l_time_staking_str) != 6)
        return TIME_ERROR;

    char l_time_staking_month_str[3] = {l_time_staking_str[2], l_time_staking_str[3], 0};
    int l_time_staking_month = atoi(l_time_staking_month_str);
    if (l_time_staking_month < 1 || l_time_staking_month > 12)
        return TIME_ERROR;

    char l_time_staking_day_str[3] = {l_time_staking_str[4], l_time_staking_str[5], 0};
    int l_time_staking_day = atoi(l_time_staking_day_str);
    if (l_time_staking_day < 1 || l_time_staking_day > 31)
        return TIME_ERROR;


    l_time_staking = dap_time_from_str_simplified(l_time_staking_str);
    if (0 == l_time_staking)
        return TIME_ERROR;
    dap_time_t l_time_now = dap_time_now();
    if (l_time_staking < l_time_now)
        return TIME_ERROR;
    l_time_staking  -= l_time_now;

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-reinvest", &l_reinvest_percent_str)
    && NULL != l_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_coins_to_balance(l_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_coins_to_balance("100.0")) == 1)
            return REINVEST_ARG_ERROR;
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(l_reinvest_percent_str);
            if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100)
                return REINVEST_ARG_ERROR;
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
    }

    if(NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path))) {
        dap_string_append_printf(output_line, "'%s'", l_wallet_str);
        return WALLET_OPEN_ERROR;
    } else {
        dap_string_append_printf(output_line, "%s\n", dap_chain_wallet_check_bliss_sign(l_wallet));
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

    // Make transfer transaction
    dap_chain_datum_t *l_datum = s_stake_lock_datum_create(l_net, l_key_from,
                                                           l_ticker_str, l_value, l_value_fee,
                                                           l_time_staking, l_reinvest_percent,
                                                           l_delegated_ticker_str, l_value_delegated);
    dap_chain_wallet_close(l_wallet);

    l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
    DAP_DEL_Z(l_datum);

    if (l_hash_str)
        dap_string_append_printf(output_line, "TX STAKE LOCK CREATED\nSuccessfully hash = %s\nSave to take!\n", l_hash_str);
    else {
        DAP_DEL_Z(l_addr_holder);
        return CREATE_LOCK_TX_ERROR;
    }

    DAP_DEL_Z(l_hash_str);
    DAP_DEL_Z(l_addr_holder);
    DAP_DEL_Z(l_hash_str);

    return STAKE_NO_ERROR;
}

static enum error_code s_cli_take(int a_argc, char **a_argv, int a_arg_index, dap_string_t *output_line)
{
    const char *l_net_str, *l_ticker_str, *l_wallet_str, *l_tx_str, *l_tx_burning_str, *l_chain_str, *l_value_fee_str;
    l_net_str = l_ticker_str = l_wallet_str = l_tx_str = l_tx_burning_str = l_chain_str = l_value_fee_str = NULL;
    dap_chain_net_t						*l_net				=	NULL;
    const char							*l_wallets_path		=	dap_chain_wallet_get_path(g_config);
    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    int									l_prev_cond_idx		=	0;
    uint256_t							l_value_delegated	= 	{};
    uint256_t                           l_value_fee     	=	{};
    char 								*l_datum_hash_str;
    dap_ledger_t						*l_ledger;
    dap_chain_wallet_t					*l_wallet;
    dap_hash_fast_t						l_tx_hash;
    dap_chain_datum_tx_t				*l_cond_tx;
    dap_chain_tx_out_cond_t				*l_tx_out_cond;
    dap_enc_key_t						*l_owner_key;
    dap_chain_datum_t					*l_datum;
    dap_chain_t							*l_chain;
    dap_chain_datum_token_t				*l_delegated_token;
    dap_tsd_t							*l_tsd;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section;

    dap_string_append_printf(output_line, "---> TAKE <---\n");

    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type, "base58"))
        return HASH_TYPE_ARG_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
    ||	NULL == l_net_str)
        return NET_ARG_ERROR;

    if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
        dap_string_append_printf(output_line, "'%s'", l_net_str);
        return NET_ERROR;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
        &&	l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if(!l_chain)
        return CHAIN_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_str)
    ||	NULL == l_tx_str)
        return TX_ARG_ERROR;

    if (dap_chain_hash_fast_from_str(l_tx_str, &l_tx_hash))
        return HASH_IS_BLANK_ERROR;

    l_ledger = l_net->pub.ledger;

    l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_tx_hash);

    if (NULL == (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK,
                                                                 &l_prev_cond_idx)))
        return NO_TX_ERROR;

    if (l_tx_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK)
        return NO_VALID_SUBTYPE_ERROR;

    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_hash, l_prev_cond_idx, NULL)) {
        return IS_USED_OUT_ERROR;
    }

    if (NULL == (l_ticker_str = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash)))
        return TX_TICKER_ERROR;

    if (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX ||
            l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT) {

        dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);

        if (NULL == (l_delegated_token = dap_ledger_token_ticker_check(l_ledger, l_delegated_ticker_str))
            ||	(l_delegated_token->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)
            ||	!l_delegated_token->header_native_decl.tsd_total_size
            ||	NULL == (l_tsd = dap_tsd_find(l_delegated_token->data_n_tsd,
                                              l_delegated_token->header_native_decl.tsd_total_size,
                                              DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
            dap_string_append_printf(output_line, "'%s'", l_delegated_ticker_str);
            return NO_DELEGATED_TOKEN_ERROR;
        }

        l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
        if (strcmp(l_ticker_str, (char*)l_tsd_section->ticker_token_from))
            return TOKEN_ERROR;

        if (!IS_ZERO_256(l_tsd_section->emission_rate)) {
            MULT_256_COIN(l_tx_out_cond->header.value, l_tsd_section->emission_rate, &l_value_delegated);
            if (IS_ZERO_256(l_value_delegated))
                return COINS_FORMAT_ERROR;
        }
    }

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str)
    ||	!l_wallet_str)
        return WALLET_ARG_ERROR;

    if (!dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_value_fee_str)
    ||	!l_value_fee_str)
        return FEE_ARG_ERROR;

    if (IS_ZERO_256( (l_value_fee = dap_chain_balance_scan(l_value_fee_str)) ))
        return FEE_FORMAT_ERROR;

    if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path)))
        return WALLET_OPEN_ERROR;
    else
        dap_string_append_printf(output_line, "%s\n", dap_chain_wallet_check_bliss_sign(l_wallet));


    if (NULL == (l_owner_key = dap_chain_wallet_get_key(l_wallet, 0))) {
        dap_chain_wallet_close(l_wallet);
        return OWNER_KEY_ERROR;
    }

    size_t l_owner_pkey_size;
    uint8_t *l_owner_pkey = dap_enc_key_serialize_pub_key(l_owner_key, &l_owner_pkey_size);
    dap_sign_t *l_owner_sign = NULL;
    dap_chain_tx_sig_t *l_tx_sign = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(
                                                            l_cond_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (l_tx_sign)
        l_owner_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sign);
    if (!l_owner_sign || l_owner_pkey_size != l_owner_sign->header.sign_pkey_size ||
            memcmp(l_owner_sign->pkey_n_sign, l_owner_pkey, l_owner_pkey_size)) {
        dap_chain_wallet_close(l_wallet);
        return OWNER_KEY_ERROR;
    }

    if (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME &&
            l_tx_out_cond->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        dap_chain_wallet_close(l_wallet);
        return NOT_ENOUGH_TIME;
    }

    l_datum = s_stake_unlock_datum_create(l_net, l_owner_key, &l_tx_hash, l_prev_cond_idx,
                                          l_ticker_str, l_tx_out_cond->header.value, l_value_fee,
                                          l_delegated_ticker_str, l_value_delegated);

    // Processing will be made according to autoprocess policy
    if (NULL == (l_datum_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type)))
        return ADD_DATUM_TX_TAKE_ERROR;

    dap_string_append_printf(output_line, "TAKE_TX_DATUM_HASH = %s\n", l_datum_hash_str);

    DAP_DEL_Z(l_datum_hash_str);
    DAP_DEL_Z(l_datum);

    return STAKE_NO_ERROR;
}

/**
 * @brief s_error_handler
 * @param errorCode
 * @param output_line
 */
static void s_error_handler(enum error_code errorCode, dap_string_t *output_line)
{
    dap_string_append_printf(output_line, "ERROR!\n");
    switch (errorCode)
    {
        case NET_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -net");
            } break;

        case NET_ERROR: {
            dap_string_append_printf(output_line, " ^^^ network not found");
            } break;

        case TOKEN_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -token");
            } break;

        case TOKEN_ERROR: {
            dap_string_append_printf(output_line, " ^^^ token ticker not found");
            } break;

        case COINS_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -coins");
            } break;

        case COINS_FORMAT_ERROR: {
            dap_string_append_printf(output_line, "Format -coins <256 bit integer>");
            } break;

        case ADDR_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -addr_holder");
            } break;

        case ADDR_FORMAT_ERROR: {
            dap_string_append_printf(output_line, "wrong address holder format");
            } break;

        case CERT_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -cert");
            } break;

        case CERT_LOAD_ERROR: {
            dap_string_append_printf(output_line, " ^^^ can't load cert");
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
            dap_string_append_printf(output_line, "stake_lock command requires parameter '-time_staking' in simplified format YYMMDD\n"
                                                                "Example: \"220610\" == \"10 june 2022 00:00\"");
            } break;

        case NO_MONEY_ERROR: {
            dap_string_append_printf(output_line, "Not enough money");
            } break;

        case WALLET_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -w");
            } break;

        case WALLET_OPEN_ERROR: {
            dap_string_append_printf(output_line, " ^^^ can't open wallet");
            } break;

        case CERT_KEY_ERROR: {
            dap_string_append_printf(output_line, " ^^^ cert doesn't contain a valid public key");
            } break;

        case WALLET_ADDR_ERROR: {
            dap_string_append_printf(output_line, " ^^^ failed to get wallet address");
            } break;

        case TX_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -tx");
            } break;

        case HASH_IS_BLANK_ERROR: {
            dap_string_append_printf(output_line, "tx hash is blank");
            } break;

        case NO_TX_ERROR: {
            dap_string_append_printf(output_line, " ^^^ could not find transaction");
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

        case NO_DELEGATED_TOKEN_ERROR: {
            dap_string_append_printf(output_line, " ^^^ delegated token not found");
            } break;

        case NO_VALID_SUBTYPE_ERROR: {
            dap_string_append_printf(output_line, "wrong subtype for transaction");
            } break;

        case IS_USED_OUT_ERROR: {
            dap_string_append_printf(output_line, "tx hash is used out");
            } break;

        case OWNER_KEY_ERROR: {
            dap_string_append_printf(output_line, "wallet key is not equal tx owner key");
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
            dap_string_append_printf(output_line, "reinvestment is set as a percentage from 0 to 100");
            } break;

        case FEE_ARG_ERROR: {
            dap_string_append_printf(output_line, "stake_lock command requires parameter -fee");
        } break;

        case FEE_FORMAT_ERROR: {
            dap_string_append_printf(output_line, "Format -fee <256 bit integer>");
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
static int s_cli_stake_lock(int a_argc, char **a_argv, char **a_str_reply)
{
    enum{
        CMD_NONE, CMD_HOLD, CMD_TAKE
    };

    enum error_code	errorCode;
    int				l_arg_index		= 1;
    int				l_cmd_num		= CMD_NONE;
    dap_string_t	*output_line	= dap_string_new(NULL);

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "hold", NULL))
        l_cmd_num = CMD_HOLD;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "take", NULL))
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

    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", output_line->str);
    dap_string_free(output_line, true);

    return 0;
}

/**
 * @brief s_give_month_str_from_month_count
 * @param month_count
 * @return
 */
static const char *s_give_month_str_from_month_count(uint8_t month_count)
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
static uint8_t s_give_month_count_from_time_str(char *time)
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
static char *s_update_date_by_using_month_count(char *time, uint8_t month_count)
{
    uint8_t		current_month;
    int			current_year;
    const char 	*month_str;
    const char 	*year_str;

    if (!time || !month_count)
        return NULL;
    if (	(current_month = s_give_month_count_from_time_str(time))	== 0	)
        return NULL;
    if (	(current_year = atoi(&time[YEAR_INDEX])) 					<= 0
    ||		current_year 												< 22
    ||		current_year 												> 99	)
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

    month_str	= s_give_month_str_from_month_count(current_month);
    year_str	= dap_itoa(current_year);

    if (*month_str
    &&	*year_str
    &&	dap_strlen(year_str) == 2) {
        memcpy(&time[MONTH_INDEX],	month_str,	3);	// 3 == len month in time RFC822 format
        memcpy(&time[YEAR_INDEX],	year_str,	2);	// 2 == len year in time RFC822 format
    } else
        return NULL;

    return time;
}

/**
 * @brief s_callback_verificator
 * @param a_ledger
 * @param a_tx_out_hash
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static bool s_stake_lock_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    dap_chain_datum_tx_t									*l_burning_tx       = NULL;
    dap_chain_datum_tx_receipt_t							*l_receipt          = NULL;
    uint256_t												l_value_delegated   = {};
    dap_hash_fast_t											l_burning_tx_hash;
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t	*l_tsd_section;
    dap_tsd_t												*l_tsd;
    dap_chain_tx_in_cond_t									*l_tx_in_cond;
    const char												*l_prev_tx_ticker;
    dap_chain_datum_token_t									*l_delegated_token;
    char 													l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];

    if (!a_owner)
        return false;

    if (a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME) {
        if (a_cond->subtype.srv_stake_lock.time_unlock > dap_time_now())
            return false;
    }
    if (NULL == (l_tx_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(
                                                            a_tx_in, 0, TX_ITEM_TYPE_IN_COND, 0)))
        return false;
    if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
        return false;
    if (NULL == (l_prev_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(
                                                            a_ledger, &l_tx_in_cond->header.tx_prev_hash)))
        return false;

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_prev_tx_ticker);

    if (a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX ||
            a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT) {
        if (NULL == (l_delegated_token = dap_ledger_token_ticker_check(a_ledger, l_delegated_ticker_str))
            ||	(l_delegated_token->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)
            ||	!l_delegated_token->header_native_decl.tsd_total_size
            ||	NULL == (l_tsd = dap_tsd_find(l_delegated_token->data_n_tsd,
                                              l_delegated_token->header_native_decl.tsd_total_size,
                                              DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
            return false;
        }

        l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);

        if (!IS_ZERO_256(l_tsd_section->emission_rate)) {
            MULT_256_COIN(a_cond->header.value, l_tsd_section->emission_rate, &l_value_delegated);
            if (IS_ZERO_256(l_value_delegated))
                return false;
        }

        l_receipt = (dap_chain_datum_tx_receipt_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_RECEIPT, 0);
        if (l_receipt) {
            if (!dap_chain_net_srv_uid_compare_scalar(l_receipt->receipt_info.srv_uid, DAP_CHAIN_NET_SRV_STAKE_LOCK_ID))
                return false;
            if (!l_receipt->exts_size)
                return false;
            l_burning_tx_hash = *(dap_hash_fast_t*)l_receipt->exts_n_signs;
            if (dap_hash_fast_is_blank(&l_burning_tx_hash))
                return false;
            l_burning_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_burning_tx_hash);
            if (!l_burning_tx) {
                char l_burning_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_hash_fast_to_str(&l_burning_tx_hash, l_burning_tx_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                char *l_take_tx_hash_str;
                dap_get_data_hash_str_static(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in), l_take_tx_hash_str);
                debug_if(s_debug_more, L_ERROR, "[Legacy] Can't find burning tx with hash %s, obtained from the receipt of take tx %s",
                       l_burning_tx_hash_str, l_take_tx_hash_str);
                return false;
            }
        } else
            l_burning_tx = a_tx_in;

        dap_list_t *l_outs_list = dap_chain_datum_tx_items_get(l_burning_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        uint256_t l_blank_out_value = {};
        for (dap_list_t *it = l_outs_list; it; it = it->next) {
            byte_t l_type = *(byte_t *)it->data;
            if (l_type == TX_ITEM_TYPE_OUT) {
                dap_chain_tx_out_t *l_out = it->data;
                if (dap_chain_addr_is_blank(&l_out->addr)) {
                    l_blank_out_value = l_out->header.value;
                    break;
                }
            } else if (l_type == TX_ITEM_TYPE_OUT_EXT) {
                dap_chain_tx_out_ext_t *l_out = it->data;
                if (dap_chain_addr_is_blank(&l_out->addr) &&
                        !strcmp(l_out->token, l_delegated_ticker_str)) {
                    l_blank_out_value = l_out->header.value;
                    break;
                }
            }
        }
        dap_list_free(l_outs_list);
        if (IS_ZERO_256(l_blank_out_value)) {
            log_it(L_ERROR, "Can't find OUT with BLANK addr in burning TX");
            return false;
        }

        if (s_debug_more) {
            char *str1 = dap_chain_balance_print(a_cond->header.value);
            char *str2 = dap_chain_balance_print(l_value_delegated);
            char *str3 = dap_chain_balance_print(l_blank_out_value);
            log_it(L_INFO, "hold/take_value: %s",	str1);
            log_it(L_INFO, "delegated_value: %s",	str2);
            log_it(L_INFO, "burning_value:   %s",	str3);
            DAP_DEL_Z(str1);
            DAP_DEL_Z(str2);
            DAP_DEL_Z(str3);
        }

        if (!EQUAL_256(l_blank_out_value, l_value_delegated)) {
            // !!! A terrible legacy crutch, TODO !!!
            SUM_256_256(l_value_delegated, GET_256_FROM_64(10), &l_value_delegated);
            if (!EQUAL_256(l_blank_out_value, l_value_delegated)) {
                log_it(L_ERROR, "Burning and delegated value mismatch");
                return false;
            }
        }
    }

    return true;
}

/**
 * @brief s_callback_verificator_added
 * @param a_tx
 * @param a_tx_item
 * @param a_tx_item_idx
 * @return
 */
static void s_stake_lock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_prev_out_item)
{
    if (a_prev_out_item)  // this is IN_COND tx
        return;
    int l_out_num = 0;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_out_num);
    if (l_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
        dap_chain_hash_fast_t l_tx_cond_hash;
        dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_cond_hash);
        dap_ledger_emission_for_stake_lock_item_add(a_ledger, &l_tx_cond_hash);
    }
}

static dap_chain_datum_t *s_stake_lock_datum_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value)
{
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    dap_ledger_t * l_ledger = a_net ? dap_ledger_by_net_name( a_net->pub.name ) : NULL;
    // check valid param
    if (!a_net || !l_ledger || !a_key_from ||
        !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || IS_ZERO_256(a_value))
        return NULL;

    const char *l_native_ticker = a_net->pub.native_ticker;
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t l_addr_fee = {}, l_addr = {};

    dap_chain_addr_fill_from_key(&l_addr, a_key_from, a_net->pub.id);
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    if (l_main_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native_ticker,
                                                                    &l_addr, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_main_ticker,
                                                                             &l_addr, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        log_it( L_ERROR, "Nothing to transfer (not enough funds)");
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
        dap_chain_id_t l_chain_id = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX)->id;
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
            log_it(L_ERROR, "Cant add conditional output");
            return NULL;
        }

        uint256_t l_value_back = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Cant add network fee output");
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
                log_it(L_ERROR, "Cant add validator's fee output");
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
                log_it( L_ERROR, "Cant add coin back output for main ticker");
                return NULL;
            }
        }
        // fee coin back
        if (!IS_ZERO_256(l_fee_transfer)) {
            SUBTRACT_256_256(l_fee_transfer, l_native_pack, &l_value_back);
            if (!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    log_it( L_ERROR, "Cant add coin back output for native ticker");
                    return NULL;
                }
            }
        }
    }

    // add delegated token emission 'out_ext'
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, a_delegated_value, a_delegated_ticker_str) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Cant add delegated token emission output");
        return NULL;
    }

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );

    return l_datum;
}

dap_chain_datum_t *s_stake_unlock_datum_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value)
{
    // check valid param
    if (!a_net | !a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || dap_hash_fast_is_blank(a_stake_tx_hash))
        return NULL;

    const char *l_native_ticker = a_net->pub.native_ticker;
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {}, l_fee_part = {};
    dap_chain_addr_t l_addr_fee = {}, l_addr = {};

    dap_chain_addr_fill_from_key(&l_addr, a_key_from, a_net->pub.id);
    dap_list_t *l_list_fee_out = NULL, *l_list_used_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    int res = compare256(l_total_fee,a_value);

    if (!IS_ZERO_256(l_total_fee)) {
        if(!l_main_native)
        {
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native_ticker,
                                                                    &l_addr, l_total_fee, &l_fee_transfer);
            if (!l_list_fee_out) {
                log_it(L_WARNING, "Not enough funds to pay fee");
                return NULL;
            }
        }
        else if(res == 1){
            SUBTRACT_256_256(l_total_fee, a_value, &l_fee_part);
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native_ticker,
                                                                    &l_addr, l_fee_part, &l_fee_transfer);
            if (!l_list_fee_out) {
                log_it(L_WARNING, "Not enough funds to pay fee");
                return NULL;
            }
        }        
    }
    if (!IS_ZERO_256(a_delegated_value)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, a_delegated_ticker_str,
                                                                                 &l_addr, a_delegated_value, &l_value_transfer);
        if(!l_list_used_out) {
            log_it( L_ERROR, "Nothing to transfer (not enough delegated tokens)");
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
            if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker)){
                dap_chain_datum_tx_delete(l_tx);
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
                return NULL;
            }
        }
        // coin back
        //SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
        if(l_main_native){
            if(res == 1)
            {
                SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
            }
            else
            {
                SUBTRACT_256_256(a_value, l_value_pack, &l_value_back);
            }
            if(!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, a_main_ticker)!=1) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }
        } else if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, a_value, a_main_ticker)!=1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
    }

    // add burning 'out_ext'
    if (!IS_ZERO_256(a_delegated_value)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &c_dap_chain_addr_blank,
                                               a_delegated_value, a_delegated_ticker_str) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, a_delegated_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, a_delegated_ticker_str) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);

    DAP_DELETE(l_tx);

    return l_datum;
}
