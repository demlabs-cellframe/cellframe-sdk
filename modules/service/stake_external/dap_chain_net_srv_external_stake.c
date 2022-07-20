/*
 * Authors:
 * Davlet Sibgatullin <davlet.sibgatullin@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

#include "dap_chain_net_srv_external_stake.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_mempool.h"

#define LOG_TAG "dap_chain_net_external_stake"

static int s_cli_srv_external_stake(int a_argc, char **a_argv, char **a_str_reply);

bool dap_chain_net_srv_external_stake_init(void)
{
	dap_chain_node_cli_cmd_item_create("stake_ext", s_cli_srv_external_stake, "External stake service commands",
									   "stake_ext hold -net <net name> -wallet <wallet name> -chain <chain> -chain_emission <chain>\n"
									   			"-months <from 1 to 8 (1 unit is equal to 3 months)> -token <ticker> -coins <value> -cert <name>\n"
									   			"stake_ext take"
	);

	return true;
}

static dap_chain_datum_tx_receipt_t *s_external_stake_receipt_create(dap_hash_fast_t hash_burning_transaction, const char *token, uint256_t datoshi_burned)
{
	uint32_t l_ext_size	= sizeof(dap_hash_fast_t) + dap_strlen(token) + 1;
	uint8_t *l_ext		= DAP_NEW_S_SIZE(uint8_t, l_ext_size);

	memcpy(l_ext, &hash_burning_transaction, sizeof(dap_hash_fast_t));
	strcpy((char *)&l_ext[sizeof(dap_hash_fast_t)], token);

	dap_chain_net_srv_price_unit_uid_t l_unit	= { .uint32 = SERV_UNIT_UNDEFINED};
	dap_chain_net_srv_uid_t l_uid				= { .uint64 = DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID };
	dap_chain_datum_tx_receipt_t *l_receipt		= dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, datoshi_burned,
																				 l_ext, l_ext_size);
	return l_receipt;
}

static error_code s_cli_srv_external_stake_hold(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
	const char *l_net_str, *l_token_str, *l_coins_str, *l_wallet_str, *l_cert_str, *l_chain_str, *l_chain_emission_str, *l_months_str;
	l_net_str = l_token_str = l_coins_str = l_wallet_str = l_cert_str = l_chain_str = l_chain_emission_str = l_months_str = NULL;
	const char *l_wallets_path = dap_chain_wallet_get_path(g_config);
	dap_chain_net_t			*l_net				= NULL;
	dap_chain_t				*l_chain			= NULL;
	dap_chain_t				*l_chain_emission	= NULL;
	dap_chain_net_srv_uid_t	l_uid				= { .uint64 = DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID };
	char					*l_hash_str;
	dap_hash_fast_t			*l_tx_cond_hash;
	dap_enc_key_t			*l_key_from;
	dap_pkey_t				*l_key_cond;
	uint256_t 				l_value;
	dap_chain_wallet_t		*l_wallet;
	dap_chain_addr_t		*l_addr_holder;
	dap_cert_t				*l_cert;
	int 					l_arg_index			= a_arg_index;
	int						l_months			= 0;

	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-months", &l_months_str)
	||	NULL == l_months_str
	||	(l_months = atoi(l_months_str)) > 8
	||	l_months < 1)
		return MONTHS_ERROR;

	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str)
	||	NULL == l_net_str)
		return NET_ARG_ERROR;

	if (NULL == (l_net = dap_chain_net_by_name(l_net_str))) {
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_net_str);
		return NET_ERROR;
	}

	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_str)
	||	NULL == l_token_str)
		return TOKEN_ARG_ERROR;

	if (NULL == dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_str)) {
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_token_str);
		return TOKEN_ERROR;
	}

	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_coins_str)
	||	NULL == l_coins_str)
		return COINS_ARG_ERROR;

	if (IS_ZERO_256( (l_value = dap_chain_balance_scan(l_coins_str)) ))
		return COINS_FORMAT_ERROR;
/*
	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr_holder", &l_addr_holder_str)
	||	NULL == l_addr_holder_str)
		return ADDR_ARG_ERROR;

	if (NULL == (l_addr_holder = dap_chain_addr_from_str(l_addr_holder_str)))
		return ADDR_FORMAT_ERROR;
*/
	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str)
	||	NULL == l_cert_str)
		return CERT_ARG_ERROR;

	if (NULL == (l_cert = dap_cert_find_by_name(l_cert_str))) {
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_cert_str);
		return CERT_LOAD_ERROR;
	}

	if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_str)
	&&	l_chain_str)
		l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
	else
		l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
	if(!l_chain)
		return CHAIN_ERROR;

	if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-chain_emission", &l_chain_emission_str)
	&&	l_chain_emission_str)
		l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
	else
		l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_EMISSION);
	if(!l_chain_emission)
		return CHAIN_EMISSION_ERROR;

	if (!dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str)
	||	NULL == l_wallet_str)
		return WALLET_ARG_ERROR;

	if(NULL == (l_wallet = dap_chain_wallet_open(l_wallet_str, l_wallets_path))) {
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_wallet_str);
		return WALLET_OPEN_ERROR;
	}

	if (compare256(dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_token_str), l_value) == -1) {
		dap_chain_wallet_close(l_wallet);
		return NO_MONEY_ERROR;
	}

	if (NULL == (l_addr_holder = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id))) {
		dap_chain_wallet_close(l_wallet);
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_wallet_str);
		return WALLET_ADDR_ERROR;
	}

	l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
	if (NULL == (l_key_cond = dap_pkey_from_enc_key(l_cert->enc_key))) {
		dap_chain_wallet_close(l_wallet);
		dap_chain_node_cli_set_reply_text(a_str_reply, "'%s'", l_cert_str);
		return CERT_KEY_ERROR;
	}

	l_tx_cond_hash = dap_chain_mempool_tx_create_cond_external_stake(l_net, l_key_from, l_key_cond, l_token_str,
																	 l_value, l_uid, l_addr_holder, l_months, time(NULL));

	dap_chain_wallet_close(l_wallet);
	DAP_DEL_Z(l_key_cond);

	l_hash_str = (l_tx_cond_hash) ? dap_chain_hash_fast_to_str_new(l_tx_cond_hash) : NULL;

	if (l_hash_str)
		dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully hash=%s\n", l_hash_str);
	else
		return ERROR;

	DAP_DEL_Z(l_hash_str);

	return NO_ERROR;
}

static error_code s_cli_srv_external_stake_take(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
	return NO_ERROR;
}

static void s_error_handler(error_code errorCode, char **a_str_reply)
{
	switch (errorCode)
	{
		case NET_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -net");
			} return;

		case NET_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - network not found");
			} return;

		case TOKEN_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -token");
			} return;

		case TOKEN_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - token ticker not found");
			} return;

		case COINS_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -coins");
			} return;

		case COINS_FORMAT_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "format -coins <256 bit integer>");dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -addr_holder");
			} return;

		case ADDR_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -addr_holder");
			} return;

		case ADDR_FORMAT_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "wrong address holder format");
			} return;

		case CERT_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -cert");
			} return;

		case CERT_LOAD_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - can't load cert");
			} return;

		case CHAIN_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command requires parameter '-chain'.\n"
														   				"you can set default datum type in chain configuration file");
			} return;

		case CHAIN_EMISSION_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command requires parameter '-chain_emission'.\n"
														   				"you can set default datum type in chain configuration file");
			} return;

		case MONTHS_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command requires parameter '-months'.\n"
														   				"use values from 1 to 8. 1 unit equals 3 months.\n"
																		   "for example: if you need 1 year - write 4");
			} return;

		case NO_MONEY_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "Not enough money");
			} return;

		case WALLET_ARG_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "stake_ext command required parameter -wallet");
			} return;

		case WALLET_OPEN_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - can't open wallet");
			} return;

		case CERT_KEY_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - cert doesn't contain a valid public key");
			} return;

		case WALLET_ADDR_ERROR: {
			dap_chain_node_cli_set_reply_text(a_str_reply, " - failed to get wallet address");
			} return;

		default: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "unrecognized error");
			} return;
	}
}

static int s_cli_srv_external_stake(int a_argc, char **a_argv, char **a_str_reply)
{
	enum{
		CMD_NONE, CMD_HOLD, CMD_TAKE
	};

	error_code errorCode;
	int l_arg_index = 1;
	int l_cmd_num = CMD_NONE;

	if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "hold", NULL))
		l_cmd_num = CMD_HOLD;
	else if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "take", NULL))
		l_cmd_num = CMD_TAKE;

	switch (l_cmd_num) {

		case CMD_HOLD: {
			errorCode = s_cli_srv_external_stake_hold(a_argc, a_argv, l_arg_index + 1, a_str_reply);
			} break;

		case CMD_TAKE: {
			errorCode = s_cli_srv_external_stake_take(a_argc, a_argv, l_arg_index + 1, a_str_reply);
			} break;

		default: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
			} return 1;
	}

	if (NO_ERROR != errorCode)
		s_error_handler(errorCode, a_str_reply);
	else
		dap_chain_node_cli_set_reply_text(a_str_reply, "Contribution successfully made");

	return 0;
}

bool dap_chain_net_srv_stake_lock_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner)
{
	/*if (!a_owner) TODO: ???
		return false;*/

	if (a_cond->subtype.srv_external_stake.count_months % 3 != 0)
		return false;

	if (a_cond->subtype.srv_external_stake.time_unlock > time(NULL))
		return false;

	dap_list_t *l_list_receipt = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_RECEIPT, NULL);
	if (!l_list_receipt)
		return false;

	dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT,NULL);
	if (!l_list_out) {
		dap_list_free(l_list_receipt);
		return false;
	}

	dap_chain_tx_out_t *burning_transaction = NULL;

	for (dap_list_t *l_list_receipt_tmp = l_list_receipt; l_list_receipt_tmp; l_list_receipt_tmp = dap_list_next(l_list_receipt_tmp)) {
		dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t *)l_list_receipt_tmp->data;

#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
		if (l_receipt->receipt_info.srv_uid.uint64 != DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID)
			continue;
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
		if (l_receipt->receipt_info.srv_uid.uint128 != DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID)
			continue;
#endif

		dap_hash_fast_t hash_burning_transaction;
		char ticker[DAP_CHAIN_TICKER_SIZE_MAX + 1];//not used TODO: check ticker?
		if (l_receipt->exts_size) {
			memcpy(&hash_burning_transaction, l_receipt->exts_n_signs, sizeof(dap_hash_fast_t));
			strcpy(ticker, (char *)&l_receipt->exts_n_signs[sizeof(dap_hash_fast_t)]);
		}
		else
			continue;

		if (dap_hash_fast_is_blank(&hash_burning_transaction))
			continue;

		for (dap_list_t *l_list_out_tmp = l_list_out; l_list_out_tmp; l_list_out_tmp = dap_list_next(l_list_out_tmp)) {
			dap_hash_fast_t *out_tx_hash = dap_chain_node_datum_tx_calc_hash((dap_chain_datum_tx_t *)l_list_out_tmp->data);
			if (dap_hash_fast_compare(&hash_burning_transaction, out_tx_hash)) {
				burning_transaction = (dap_chain_tx_out_t *)l_list_out_tmp->data;
				DAP_DEL_Z(out_tx_hash);
				break;
			}
			DAP_DEL_Z(out_tx_hash);
		}
		if (burning_transaction)
			break;
	}

	dap_list_free(l_list_receipt);
	dap_list_free(l_list_out);

	if (!burning_transaction)
		return false;

	if (dap_hash_fast_is_blank(&burning_transaction->addr.data.hash_fast)
	&&	!compare256(burning_transaction->header.value, a_cond->subtype.srv_external_stake.value))
		return true;
	return false;
}
