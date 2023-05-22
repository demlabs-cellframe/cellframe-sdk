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
#include "dap_chain_ledger.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"

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
	NO_DELEGATE_TOKEN_ERROR		= 25,
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
	REINVEST_ARG_ERROR			= 40
};

typedef struct dap_chain_ledger_token_emission_for_stake_lock_item {
	dap_chain_hash_fast_t	datum_token_emission_for_stake_lock_hash;
	dap_chain_hash_fast_t	tx_used_out;
//	const char 				datum_token_emission_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
	UT_hash_handle hh;
} dap_chain_ledger_token_emission_for_stake_lock_item_t;

#define LOG_TAG		"dap_chain_net_stake_lock"
#define MONTH_INDEX	8
#define YEAR_INDEX	12

static int												s_cli_stake_lock(int a_argc, char **a_argv, char **a_str_reply);
static dap_chain_hash_fast_t							*dap_chain_mempool_base_tx_for_stake_lock_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
																			  dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker,
																			  dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_from);
// Callbacks
static void												s_callback_decree (dap_chain_net_srv_t * a_srv, dap_chain_net_t *a_net, dap_chain_t * a_chain,
																			  dap_chain_datum_decree_t * a_decree, size_t a_decree_size);
static bool s_stake_lock_callback_verificator_added(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_tx_item);
static bool s_stake_lock_callback_verificator(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                   dap_chain_datum_tx_t *a_tx_in, bool a_owner);
/**
 * @brief dap_chain_net_srv_external_stake_init
 * @return
 */
int dap_chain_net_srv_stake_lock_init()
{
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, s_stake_lock_callback_verificator, s_stake_lock_callback_verificator_added);
    dap_chain_node_cli_cmd_item_create("stake_lock", s_cli_stake_lock, "Stake lock service commands",
       "Command:"
	   			"stake_lock hold\n"
	   			"Required parameters:\n"
	   			"-net <net name> -wallet <wallet name> -time_staking <in YYMMDD>\n"
	    		"-token <ticker> -coins <value>\n"
				"Optional parameters:\n"
				"-cert <name> -chain <chain> -reinvest <percentage from 1 to 100>\n"
				"-no_base_tx(flag to create a transaction without base transaction)\n"
				"Command:"
    			"stake_lock take\n"
				"Required parameters:\n"
				"-net <net name> -wallet <wallet name> -tx <transaction hash>\n"
				"Optional parameters:\n"
				"-chain <chain>\n"
	);

	s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);

	dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
	dap_chain_net_srv_callbacks_t l_srv_callbacks = {};
	l_srv_callbacks.decree = s_callback_decree;

    dap_chain_net_srv_t *l_srv = dap_chain_net_srv_add(l_uid, "stake_lock", &l_srv_callbacks);
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
static void s_callback_decree (dap_chain_net_srv_t * a_srv, dap_chain_net_t *a_net, dap_chain_t * a_chain, dap_chain_datum_decree_t * a_decree, size_t a_decree_size)
{

}

/**
 * @brief s_receipt_create
 * @param hash_burning_transaction
 * @param token
 * @param datoshi_burned
 * @return
 */
static dap_chain_datum_tx_receipt_t *s_receipt_create(dap_hash_fast_t *hash_burning_transaction, const char *token, uint256_t datoshi_burned)
{
	uint32_t l_ext_size	= sizeof(dap_hash_fast_t) + dap_strlen(token) + 1;
    uint8_t *l_ext		= DAP_NEW_S_SIZE(uint8_t, l_ext_size);

	memcpy(l_ext, hash_burning_transaction, sizeof(dap_hash_fast_t));
	strcpy((char *)&l_ext[sizeof(dap_hash_fast_t)], token);

	dap_chain_net_srv_price_unit_uid_t l_unit	= { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid				= { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
	dap_chain_datum_tx_receipt_t *l_receipt		= dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, datoshi_burned,
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
static enum error_code s_cli_hold(int a_argc, char **a_argv, int a_arg_index, dap_string_t *output_line)
{
    const char *l_net_str, *l_ticker_str, *l_coins_str, *l_wallet_str, *l_cert_str, *l_chain_str, /* *l_chain_emission_str,*/ *l_time_staking_str, *l_reinvest_percent_str;
	l_net_str = l_ticker_str = l_coins_str = l_wallet_str = l_cert_str = l_chain_str = /*l_chain_emission_str =*/ l_time_staking_str = l_reinvest_percent_str = NULL;
	const char *l_wallets_path								=	dap_chain_wallet_get_path(g_config);
	char 	delegate_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{[0] = 'm'};
	dap_chain_net_t						*l_net				=	NULL;
	dap_chain_t							*l_chain			=	NULL;
//	dap_chain_t							*l_chain_emission	=	NULL;
	dap_cert_t							*l_cert				=	NULL;
	dap_pkey_t							*l_key_cond			=	NULL;
	dap_hash_fast_t 					*l_base_tx_hash		=	NULL;
	dap_chain_net_srv_uid_t				l_uid				=	{ .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
	dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
	uint256_t							l_value_delegated	=	{};
	bool								create_base_tx		=	true;
	uint256_t 							l_value;
	dap_ledger_t						*l_ledger;
	char								*l_hash_str;
	dap_hash_fast_t						*l_tx_cond_hash;
	dap_enc_key_t						*l_key_from;
	dap_chain_wallet_t					*l_wallet;
	dap_chain_addr_t					*l_addr_holder;
	dap_chain_datum_token_t 			*delegate_token;
	dap_tsd_t							*l_tsd;
	dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;

	dap_string_append_printf(output_line, "---> HOLD <---\n");

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
	||	NULL == l_net_str)
		return NET_ARG_ERROR;

	if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
		dap_string_append_printf(output_line, "'%s'", l_net_str);
		return NET_ERROR;
	}

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-token", &l_ticker_str)
	|| NULL == l_ticker_str
	|| dap_strlen(l_ticker_str) > 8) // for 'm' delegated
		return TOKEN_ARG_ERROR;

	l_ledger = l_net->pub.ledger;

	if (NULL == dap_chain_ledger_token_ticker_check(l_ledger, l_ticker_str)) {
		dap_string_append_printf(output_line, "'%s'", l_ticker_str);
		return TOKEN_ERROR;
	}

	if (dap_chain_node_cli_check_option(a_argv, a_arg_index, a_argc, "-no_base_tx") >= 0)
		create_base_tx = false;

	if (create_base_tx) {
		strcpy(delegate_ticker_str + 1, l_ticker_str);

		if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(l_ledger, delegate_ticker_str))
		||	(delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL && delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
		||	!delegate_token->header_native_decl.tsd_total_size
		||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
			dap_string_append_printf(output_line, "'%s'", delegate_ticker_str);
			return NO_DELEGATE_TOKEN_ERROR;
		}

		l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
		if (strcmp(l_ticker_str, l_tsd_section.ticker_token_from))
			return TOKEN_ERROR;
	}

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-coins", &l_coins_str)
	||	NULL == l_coins_str)
		return COINS_ARG_ERROR;

	if (IS_ZERO_256( (l_value = dap_chain_balance_scan(l_coins_str)) ))
		return COINS_FORMAT_ERROR;

	if (create_base_tx
	&&	!IS_ZERO_256(l_tsd_section.emission_rate)) {
		MULT_256_COIN(l_value, l_tsd_section.emission_rate, &l_value_delegated);
		if (IS_ZERO_256(l_value_delegated))
			return COINS_FORMAT_ERROR;
	} else
		l_value_delegated = l_value;

	dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);

	if (NULL != l_cert_str
	&&	NULL == (l_cert = dap_cert_find_by_name(l_cert_str))) {
		dap_string_append_printf(output_line, "'%s'", l_cert_str);
		return CERT_LOAD_ERROR;
	}

	if (dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
	&&	l_chain_str)
		l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
	else
		l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
	if(!l_chain)
		return CHAIN_ERROR;

/*	if (dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-chain_emission", &l_chain_emission_str)
	&&	l_chain_emission_str)
		l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
	else
		l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_EMISSION);
	if(!l_chain_emission)
		return CHAIN_EMISSION_ERROR;*/

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-wallet", &l_wallet_str)
	||	NULL == l_wallet_str)
		return WALLET_ARG_ERROR;

    // Read time staking
    if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-time_staking", &l_time_staking_str)
    ||	NULL == l_time_staking_str)
		return TIME_ERROR;

    l_time_staking = dap_time_from_str_simplified(l_time_staking_str);
    if (0 == l_time_staking)
		return TIME_ERROR;
    dap_time_t l_time_now = dap_time_now();
    if (l_time_staking < l_time_now)
        return TIME_ERROR;
    l_time_staking -= l_time_now;

	if (dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-reinvest", &l_reinvest_percent_str)
	&& NULL != l_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_coins_to_balance(l_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_coins_to_balance("100.0")) == 1)
			return REINVEST_ARG_ERROR;
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(l_reinvest_percent_str);
            if (l_reinvest_percent_int <= 0 || l_reinvest_percent_int > 100)
                return REINVEST_ARG_ERROR;
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
	}

/*________________________________________________________________________________________________________________*/

	if(NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path))) {
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

	if (NULL != l_cert
	&&	NULL == (l_key_cond = dap_pkey_from_enc_key(l_cert->enc_key))) {
		dap_chain_wallet_close(l_wallet);
		DAP_DEL_Z(l_addr_holder);
		dap_string_append_printf(output_line, "'%s'", l_cert_str);
		return CERT_KEY_ERROR;
	}

    l_tx_cond_hash = dap_chain_net_srv_stake_lock_mempool_create(l_net, l_key_from, l_key_cond,
																 l_ticker_str,l_value, l_uid,
																 l_addr_holder, l_chain, l_time_staking,
																 l_reinvest_percent, create_base_tx);

	DAP_DEL_Z(l_key_cond);

	l_hash_str = (l_tx_cond_hash) ? dap_chain_hash_fast_to_str_new(l_tx_cond_hash) : NULL;

	if (l_hash_str)
		dap_string_append_printf(output_line, "TX STAKE LOCK CREATED\nSuccessfully hash=%s\nSave to take!\n", l_hash_str);
	else {
		dap_chain_wallet_close(l_wallet);
		DAP_DEL_Z(l_addr_holder);
        return CREATE_LOCK_TX_ERROR;
	}

	DAP_DEL_Z(l_hash_str);

	if (create_base_tx) {
		l_base_tx_hash = dap_chain_mempool_base_tx_for_stake_lock_create(l_chain, l_tx_cond_hash, l_chain->id,
													  l_value_delegated, delegate_ticker_str, l_addr_holder, l_key_from);
	}

	dap_chain_wallet_close(l_wallet);

	if (create_base_tx) {
		l_hash_str = (l_base_tx_hash) ? dap_chain_hash_fast_to_str_new(l_base_tx_hash) : NULL;

		if (l_hash_str)
			dap_string_append_printf(output_line, "BASE_TX_DATUM_HASH=%s\n", l_hash_str);
		else {
			DAP_DEL_Z(l_addr_holder);
			DAP_DEL_Z(l_tx_cond_hash);
			return BASE_TX_CREATE_ERROR;
		}
	}

	DAP_DEL_Z(l_addr_holder);
	DAP_DEL_Z(l_tx_cond_hash);
	DAP_DEL_Z(l_base_tx_hash);
	DAP_DEL_Z(l_hash_str);

    return STAKE_NO_ERROR;
}

static enum error_code s_cli_take(int a_argc, char **a_argv, int a_arg_index, dap_string_t *output_line)
{
	const char *l_net_str, *l_ticker_str, *l_wallet_str, *l_tx_str, *l_tx_burning_str, *l_chain_str;
	l_net_str = l_ticker_str = l_wallet_str = l_tx_str = l_tx_burning_str = l_chain_str = NULL;
	dap_chain_net_t						*l_net				=	NULL;
	dap_chain_datum_t					*l_datum_burning_tx	=	NULL;
	const char							*l_wallets_path		=	dap_chain_wallet_get_path(g_config);
	char 	delegate_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{[0] = 'm'};
    int									l_prev_cond_idx		=	-1;
	uint256_t							l_value_delegated	= 	{};
	char 								*l_datum_hash_str;
	dap_ledger_t						*l_ledger;
	dap_chain_wallet_t					*l_wallet;
	dap_hash_fast_t						l_tx_hash;
	dap_hash_fast_t 					l_tx_burning_hash;
	dap_chain_datum_tx_receipt_t		*l_receipt;
	dap_chain_datum_tx_t				*l_tx;
	dap_chain_datum_tx_t				*l_cond_tx;
	dap_chain_tx_out_cond_t				*l_tx_out_cond;
	dap_chain_addr_t					*l_owner_addr;
	dap_enc_key_t						*l_owner_key;
	size_t								l_tx_size;
	dap_chain_datum_t					*l_datum;
	dap_chain_t							*l_chain;
	dap_chain_datum_token_t				*delegate_token;
	dap_tsd_t							*l_tsd;
	dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;

	dap_string_append_printf(output_line, "---> TAKE <---\n");

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str)
	||	NULL == l_net_str)
		return NET_ARG_ERROR;

	if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
		dap_string_append_printf(output_line, "'%s'", l_net_str);
		return NET_ERROR;
	}

	if (dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-chain", &l_chain_str)
		&&	l_chain_str)
		l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
	else
		l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
	if(!l_chain)
		return CHAIN_ERROR;

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_str)
	||	NULL == l_tx_str)
		return TX_ARG_ERROR;

	dap_chain_hash_fast_from_hex_str(l_tx_str, &l_tx_hash);

	if (dap_hash_fast_is_blank(&l_tx_hash))
		return HASH_IS_BLANK_ERROR;

	l_ledger = l_net->pub.ledger;

	l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &l_tx_hash);

    if (NULL == (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK,
                                                                 &l_prev_cond_idx)))
		return NO_TX_ERROR;

	if (l_tx_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK)
		return NO_VALID_SUBTYPE_ERROR;

    dap_hash_fast_t l_spender = { };
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_hash, l_prev_cond_idx, &l_spender)) {
        char hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str(&l_spender, hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        debug_if(s_debug_more, L_ERROR, "Already taken by %s", hash_str);
		return IS_USED_OUT_ERROR;
	}

	if (NULL == (l_ticker_str = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash)))
		return TX_TICKER_ERROR;

    if (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
		strcpy(delegate_ticker_str + 1, l_ticker_str);

		if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(l_ledger, delegate_ticker_str))
			||	(delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL && delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
			||	!delegate_token->header_native_decl.tsd_total_size
			||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
			dap_string_append_printf(output_line, "'%s'", delegate_ticker_str);
			return NO_DELEGATE_TOKEN_ERROR;
		}

		l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
		if (strcmp(l_ticker_str, l_tsd_section.ticker_token_from))
			return TOKEN_ERROR;
	}

    if ((l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX)
	&&	!IS_ZERO_256(l_tsd_section.emission_rate)) {
		MULT_256_COIN(l_tx_out_cond->header.value, l_tsd_section.emission_rate, &l_value_delegated);
		if (IS_ZERO_256(l_value_delegated))
			return COINS_FORMAT_ERROR;
	} else
		l_value_delegated = l_tx_out_cond->header.value;

	if (!dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-wallet", &l_wallet_str)
	||	NULL == l_wallet_str)
		return WALLET_ARG_ERROR;

	if (NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path)))
		return WALLET_OPEN_ERROR;

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

    if (NULL == (l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(l_wallet, l_net->pub.id))) {
        dap_chain_wallet_close(l_wallet);
        return WALLET_ADDR_ERROR;
    }

    if (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME &&
            l_tx_out_cond->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_owner_addr);
        return NOT_ENOUGH_TIME;
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


    if (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
        if (dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, "-tx_burning", &l_tx_burning_str) && l_tx_burning_str) {
            log_it(L_INFO, "Attempt to take with provided burning hash %s", l_tx_burning_str);
            /* A secret param with already present burning tx was provided */
            dap_chain_hash_fast_from_hex_str(l_tx_burning_str, &l_tx_burning_hash);
        } else {
            /* Create a burning tx */
            dap_chain_addr_t l_addr_blank = {0};
            if (NULL == (l_datum_burning_tx = dap_chain_burning_tx_create(l_chain, l_owner_key, l_owner_addr, &l_addr_blank,
                                                                          delegate_ticker_str, l_value_delegated))) {
                dap_chain_wallet_close(l_wallet);
                DAP_DEL_Z(l_owner_addr);
                dap_chain_datum_tx_delete(l_tx);
                return CREATE_BURNING_TX_ERROR;
            }
            dap_hash_fast(l_datum_burning_tx->data, l_datum_burning_tx->header.data_size, &l_tx_burning_hash);
        }

		if (NULL == (l_receipt = s_receipt_create(&l_tx_burning_hash, delegate_ticker_str, l_value_delegated))) {
			dap_chain_wallet_close(l_wallet);
			DAP_DEL_Z(l_owner_addr);
			dap_chain_datum_tx_delete(l_tx);
			DAP_DEL_Z(l_datum_burning_tx);
			return CREATE_RECEIPT_ERROR;
		}

		dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
	}

	if(dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
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

    if (!l_tx_burning_str && (l_tx_out_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX)) {
		if (NULL == (l_datum_hash_str = dap_chain_mempool_datum_add(l_datum_burning_tx, l_chain))) {
			DAP_DEL_Z(l_datum_burning_tx);
			DAP_DEL_Z(l_datum);
			return ADD_DATUM_BURNING_TX_ERROR;
		}

		dap_string_append_printf(output_line, "BURNING_TX_DATUM_HASH=%s\n", l_datum_hash_str);
		DAP_DEL_Z(l_datum_burning_tx);
		DAP_DEL_Z(l_datum_hash_str);
	}

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
static void s_error_handler(enum error_code errorCode, dap_string_t *output_line)
{
	dap_string_append_printf(output_line, "ERROR!\n");
	switch (errorCode)
	{
		case NET_ARG_ERROR: {
			dap_string_append_printf(output_line, "stake_lock command required parameter -net");
			} break;

		case NET_ERROR: {
			dap_string_append_printf(output_line, " ^^^ network not found");
			} break;

		case TOKEN_ARG_ERROR: {
			dap_string_append_printf(output_line, "stake_lock command required parameter -token");
			} break;

		case TOKEN_ERROR: {
			dap_string_append_printf(output_line, " ^^^ token ticker not found");
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
			dap_string_append_printf(output_line, "stake_lock command required parameter -wallet");
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
			dap_string_append_printf(output_line, "stake_lock command required parameter -tx");
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
static int s_cli_stake_lock(int a_argc, char **a_argv, char **a_str_reply)
{
	enum{
		CMD_NONE, CMD_HOLD, CMD_TAKE
	};

    enum error_code	errorCode;
	int				l_arg_index		= 1;
	int				l_cmd_num		= CMD_NONE;
	dap_string_t	*output_line	= dap_string_new(NULL);

	if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "hold", NULL))
		l_cmd_num = CMD_HOLD;
	else if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "take", NULL))
		l_cmd_num = CMD_TAKE;

	switch (l_cmd_num) {

		case CMD_HOLD: {
            errorCode = s_cli_hold(a_argc, a_argv, l_arg_index + 1, output_line);
			} break;

		case CMD_TAKE: {
            errorCode = s_cli_take(a_argc, a_argv, l_arg_index + 1, output_line);
			} break;

		default: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            dap_string_free(output_line, false);
			} return 1;
	}

    if (STAKE_NO_ERROR != errorCode)
		s_error_handler(errorCode, output_line);
	else
		dap_string_append_printf(output_line, "Contribution successfully made");

	dap_chain_node_cli_set_reply_text(a_str_reply, output_line->str);
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
static bool s_stake_lock_callback_verificator(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                   dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
	UNUSED(a_tx_out_hash);
	dap_chain_datum_tx_t									*burning_tx					= NULL;
	dap_chain_tx_out_t										*burning_transaction_out	= NULL;
	dap_chain_datum_tx_receipt_t							*l_receipt					= NULL;
	uint256_t												l_value_delegated			= {};
	dap_hash_fast_t											hash_burning_transaction;
	dap_chain_datum_token_tsd_delegate_from_stake_lock_t	l_tsd_section;
	dap_tsd_t												*l_tsd;
	dap_chain_tx_out_t										*l_tx_out;
	dap_chain_tx_in_cond_t									*l_tx_in_cond;
	const char												*l_tx_ticker;
	dap_chain_datum_token_t									*delegate_token;
	char 													delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];

    if (!a_owner) {
        log_it(L_ERROR, "Verificator: no owner");
        return false;
    }

    if (a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME) {
        if (a_cond->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
            char l_time_str[32];
            dap_time_t l_time = a_cond->subtype.srv_stake_lock.time_unlock;
            dap_ctime_r(&l_time, l_time_str);
            log_it(L_ERROR, "Verificator: unlock time [%s] has not yet come", l_time_str);
            return false;
        }
    }

    if (a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
        l_receipt = (dap_chain_datum_tx_receipt_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_RECEIPT, 0);
        if (!l_receipt) {
            log_it(L_ERROR, "Verificator: no receipt item found");
			return false;
        }

#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
        if (l_receipt->receipt_info.srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_LOCK_ID) {
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
        if (l_receipt->receipt_info.srv_uid.uint128 != DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID) {
#endif
            log_it(L_ERROR, "Verificator: service ID in receipt %lu != %d", l_receipt->receipt_info.srv_uid.uint64, DAP_CHAIN_NET_SRV_STAKE_LOCK_ID);
            return false;
        }

        if (!l_receipt->exts_size) {
            log_it(L_ERROR, "Verificator: exts size in receipt is 0");
            return false;
        }

        hash_burning_transaction = *(dap_hash_fast_t*)l_receipt->exts_n_signs;
        if (dap_hash_fast_is_blank(&hash_burning_transaction)) {
            log_it(L_ERROR, "Verificator: blank burning transaction hash in the receipt");
			return false;
        } else {
            char l_burning_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&hash_burning_transaction, l_burning_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_DEBUG, "Burning tx hash: %s", l_burning_hash_str);
        }
        strcpy(delegated_ticker, (char *)&l_receipt->exts_n_signs[sizeof(dap_hash_fast_t)]);
	}

	l_tx_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_OUT, 0);

    if (!l_tx_out) {
        log_it(L_ERROR, "Verificator: no out item in this tx");
		return false;
    }

    if (!EQUAL_256(a_cond->header.value, l_tx_out->header.value)) {
        char    *l_cond_val = dap_chain_balance_print(a_cond->header.value),
                *l_tx_out_val = dap_chain_balance_print(l_tx_out->header.value);
        log_it(L_ERROR, "Verificator: values mismatch [%s != %s]", l_cond_val, l_tx_out_val);
        DAP_DELETE(l_tx_out_val);
        DAP_DELETE(l_cond_val);
		return false;
    }

    if (a_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
		if (NULL == (delegate_token = dap_chain_ledger_token_ticker_check(a_ledger, delegated_ticker))
			||	(delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL && delegate_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
			||	!delegate_token->header_native_decl.tsd_total_size
			||	NULL == (l_tsd = dap_tsd_find(delegate_token->data_n_tsd, delegate_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
            log_it(L_ERROR, "Verificator: something wrong with delegate token");
			return false;
		}

		l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);

        if (NULL == (l_tx_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_IN_COND, 0))) {
            log_it(L_ERROR, "Verificator: no IN_COND item found");
			return false;
        }
        if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash)) {
            log_it(L_ERROR, "Verificator: previous tx hash in IN_COND is empty");
			return false;
        }
        if (NULL == (l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_in_cond->header.tx_prev_hash))) {
            log_it(L_ERROR, "Verificator: token ticker in previous tx in IN_COND not found");
			return false;
        }
        if (strcmp(l_tx_ticker, l_tsd_section.ticker_token_from)) {
            log_it(L_ERROR, "Verificator: tickers mismatch %s != %s", l_tx_ticker, l_tsd_section.ticker_token_from);
			return false;
        }
        if (NULL == (l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &hash_burning_transaction))) {
            log_it(L_ERROR, "Verificator: token ticker in burning tx not found");
			return false;
        }
        if (strcmp(l_tx_ticker, delegated_ticker)) {
            log_it(L_ERROR, "Verificator: burning ticker mismatch: %s != %s", l_tx_ticker, delegated_ticker);
			return false;
        }

        int l_tx_burning_blank_out_idx = 0;

        burning_tx = dap_chain_ledger_tx_find_by_hash(a_ledger, &hash_burning_transaction);
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(burning_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        for(dap_list_t *it = l_list_out_items; it; it = dap_list_next(it), ++l_tx_burning_blank_out_idx) {
            dap_chain_tx_item_type_t l_type = *(byte_t *)it->data;
            if (l_type == TX_ITEM_TYPE_OUT) {
                dap_chain_tx_out_t *l_tx_out = it->data;
                dap_chain_addr_t l_addr = l_tx_out->addr;
                if (dap_chain_addr_is_blank(&l_addr)) {
                    burning_transaction_out = l_tx_out;
                    break;
                }
            }
        }
        dap_list_free(l_list_out_items);

        if (!burning_transaction_out) {
            log_it(L_ERROR, "Verificator: no burning tx out");
            return false;
        }

        {
            dap_hash_fast_t l_spender_hash = { };
            char l_burning_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&hash_burning_transaction, l_burning_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_INFO, "Check burning tx %s : 'out' item %d", l_burning_hash_str, l_tx_burning_blank_out_idx);
            if (dap_chain_ledger_tx_hash_is_used_out_item(a_ledger, &hash_burning_transaction, l_tx_burning_blank_out_idx, &l_spender_hash)) {
                char l_spender_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(&l_spender_hash, l_spender_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                log_it(L_ERROR, "Verificator: burning tx %s out item no. %d is already used by %s", l_burning_hash_str, l_tx_burning_blank_out_idx, l_spender_hash_str);
                return false;
            }
        }

		if (!IS_ZERO_256(l_tsd_section.emission_rate)) {
			MULT_256_COIN(l_tx_out->header.value, l_tsd_section.emission_rate, &l_value_delegated);
            if (IS_ZERO_256(l_value_delegated)) {
                log_it(L_ERROR, "Verificator: delegated token value is 0");
                return false;
            }
		} else
			l_value_delegated = l_tx_out->header.value;

        if (!EQUAL_256(burning_transaction_out->header.value, l_value_delegated)) {
            char    *l_brn_tx_val = dap_chain_balance_print(burning_transaction_out->header.value),
                    *l_delegated_val = dap_chain_balance_print(l_value_delegated);
            log_it(L_ERROR, "Verificator: delegated token value mismatch: %s != %s", l_brn_tx_val, l_delegated_val);
            DAP_DELETE(l_brn_tx_val);
            DAP_DELETE(l_delegated_val);
            return false;
        }

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
static bool s_stake_lock_callback_verificator_added(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_tx_item)
{
    if (a_tx_item)  // this is IN_COND tx
        return true;
    int l_out_num = -1;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_out_num);
    if (l_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
        dap_chain_hash_fast_t l_key_hash;
        dap_hash_fast( a_tx, dap_chain_datum_tx_get_size(a_tx), &l_key_hash);
        if (dap_hash_fast_is_blank(&l_key_hash))
            return false;
        dap_chain_ledger_emission_for_stake_lock_item_add(a_ledger, &l_key_hash);
    }
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
static dap_chain_datum_t* s_mempool_create(dap_chain_net_t *a_net,
                                                   dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                                   const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                   uint256_t a_value, dap_chain_net_srv_uid_t a_srv_uid,
                                                   dap_chain_addr_t *a_addr_holder, dap_time_t a_time_staking,
                                                   uint256_t a_reinvest_percent, bool create_base_tx)
{
    dap_ledger_t * l_ledger = a_net ? dap_chain_ledger_by_net_name( a_net->pub.name ) : NULL;
    // check valid param
    if (!a_net || !l_ledger || !a_key_from ||
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
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                             &l_addr_from, a_value, &l_value_transfer);
    if(!l_list_used_out) {
        log_it( L_ERROR, "Nothing to tranfer (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out_cond' and 'out' items
    {
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_net_srv_stake_lock_create_cond_out(a_key_cond, a_srv_uid, a_value, a_time_staking, a_reinvest_percent, create_base_tx);
        if(l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
			dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond);
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
            if(dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it( L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );

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
dap_chain_tx_out_cond_t *dap_chain_net_srv_stake_lock_create_cond_out(dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                                    uint64_t a_time_staking, uint256_t a_reinvest_percent, bool create_base_tx)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_lock.reinvest_percent = a_reinvest_percent;
    if (a_time_staking) {
        l_item->subtype.srv_stake_lock.time_unlock = dap_time_now() + a_time_staking;
        l_item->subtype.srv_stake_lock.flags |= DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME;
	}
	if (create_base_tx)
        l_item->subtype.srv_stake_lock.flags |= DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX;
    if (a_key)
        dap_hash_fast(a_key->pkey, a_key->header.size, &l_item->subtype.srv_stake_lock.pkey_delegated);

    return l_item;
}

json_object *dap_chain_net_srv_stake_lock_cond_out_to_json(dap_chain_tx_out_cond_t *a_stake_lock) {
    if (a_stake_lock->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
        json_object *l_object = json_object_new_object();
        char *l_value = dap_chain_balance_print(a_stake_lock->header.value);
        json_object *l_obj_value = json_object_new_string(l_value);
        DAP_DELETE(l_value);
        json_object *l_obj_srv_uid = json_object_new_uint64(a_stake_lock->header.srv_uid.uint64);
        char *l_reinvest_precent = dap_chain_balance_print(a_stake_lock->subtype.srv_stake_lock.reinvest_percent);
        json_object *l_obj_reinvest_percent = json_object_new_string(l_reinvest_precent);
        DAP_DELETE(l_reinvest_precent);
        json_object *l_obj_time_unlock = json_object_new_uint64(a_stake_lock->subtype.srv_stake_lock.time_unlock);
        json_object *l_obj_flags = json_object_new_uint64(a_stake_lock->subtype.srv_stake_lock.flags);
        char *l_pkey_delegate_hash = dap_hash_fast_to_str_new(&a_stake_lock->subtype.srv_stake_lock.pkey_delegated);
        json_object *l_obj_pkey_delegate_hash = json_object_new_string(l_pkey_delegate_hash);
        DAP_DELETE(l_pkey_delegate_hash);
        json_object_object_add(l_object, "value", l_obj_value);
        json_object_object_add(l_object, "srvUID", l_obj_srv_uid);
        json_object_object_add(l_object, "reinvestPercent", l_obj_reinvest_percent);
        json_object_object_add(l_object, "timeUnlock", l_obj_time_unlock);
        json_object_object_add(l_object, "flags", l_obj_flags);
        json_object_object_add(l_object, "pkeyDelegateHash", l_obj_pkey_delegate_hash);
        return l_object;
    }
    return NULL;
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
dap_chain_hash_fast_t* dap_chain_net_srv_stake_lock_mempool_create(dap_chain_net_t *a_net,
                                                                       dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                                                       const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                                       uint256_t a_value, dap_chain_net_srv_uid_t a_srv_uid,
                                                                       dap_chain_addr_t *a_addr_holder, dap_chain_t *a_chain,
                                                                       uint64_t a_time_staking, uint256_t a_reinvest_percent,
																	   bool create_base_tx)
{
    // Make transfer transaction
    dap_chain_datum_t *l_datum = s_mempool_create(a_net, a_key_from, a_key_cond, a_token_ticker, a_value, a_srv_uid,
												  a_addr_holder, a_time_staking, a_reinvest_percent, create_base_tx);

    if(!l_datum)
        return NULL;

    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)&(l_datum->data);
    size_t l_tx_size = l_datum->header.data_size;

    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash);

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);

    if( dap_chain_global_db_gr_set( l_key_str, l_datum, dap_chain_datum_size(l_datum), l_gdb_group) == true ) {
        log_it(L_NOTICE, "Transaction %s placed in mempool group %s", l_key_str, l_gdb_group);
    }

    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}

dap_chain_datum_t *dap_chain_burning_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
											 const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
											 const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
											 uint256_t a_value)
{
	// check valid param
	if(!a_chain | !a_key_from || ! a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
	   !dap_chain_addr_check_sum(a_addr_from) || !a_addr_to || !dap_chain_addr_check_sum(a_addr_to) || IS_ZERO_256(a_value))
		return NULL;

	// find the transactions from which to take away coins
	uint256_t l_value_transfer = {}; // how many coins to transfer
	dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
																			 a_addr_from, a_value, &l_value_transfer);
	if (!l_list_used_out) {
		log_it(L_WARNING,"Not enough funds to transfer");
		return NULL;
	}
	// create empty transaction
	dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
	// add 'in' items
	{
		uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
		assert(EQUAL_256(l_value_to_items, l_value_transfer));
		dap_list_free_full(l_list_used_out, free);
	}
	// add 'out' items
	{
		uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
		if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) == 1) {
			SUM_256_256(l_value_pack, a_value, &l_value_pack);
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

static dap_chain_hash_fast_t *dap_chain_mempool_base_tx_for_stake_lock_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
														dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker,
														dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_from)
{
	char *l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(a_chain);
	// create first transaction (with tx_token)
	dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
	l_tx->header.ts_created = time(NULL);
	dap_chain_hash_fast_t l_tx_prev_hash = { 0 };
	// create items

	dap_chain_tx_token_t *l_tx_token = dap_chain_datum_tx_item_token_create(a_emission_chain_id, a_emission_hash, a_ticker);
	dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, 0);
	dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(a_addr_to, a_emission_value);

	// pack items to transaction
	dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_token);
	dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
	dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);

	if (a_key_from) {
		if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) < 0) {
			log_it(L_WARNING, "Private key not valid");
			return NULL;
		}
	} else {
		log_it(L_WARNING, "No private key for base TX!");
		return NULL;
	}

	DAP_DEL_Z(l_tx_token);
	DAP_DEL_Z(l_in);
	DAP_DEL_Z(l_out);

	size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);

	// Pack transaction into the datum
	dap_chain_datum_t * l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
	size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
	DAP_DEL_Z(l_tx);
	// calc datum hash
	dap_chain_hash_fast_t *l_datum_tx_hash = DAP_NEW(dap_hash_fast_t);
	dap_hash_fast(l_datum_tx->data, l_datum_tx->header.data_size, l_datum_tx_hash);
	char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(l_datum_tx_hash);
	// Add to mempool tx token
	bool l_placed = dap_chain_global_db_gr_set(l_tx_hash_str, l_datum_tx,
											   l_datum_tx_size, l_gdb_group_mempool_base_tx);
	DAP_DEL_Z(l_tx_hash_str);
	DAP_DELETE(l_datum_tx);
	if (!l_placed) {
		return NULL;
	}
	return l_datum_tx_hash;
}
