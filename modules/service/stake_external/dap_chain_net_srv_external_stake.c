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

#define LOG_TAG "dap_chain_net_external_stake"

static int s_cli_srv_external_stake(int a_argc, char **a_argv, char **a_str_reply);

int dap_chain_net_srv_external_stake_init(void)
{
	dap_chain_node_cli_cmd_item_create("stake_ext", s_cli_srv_external_stake, "External stake service commands",
									   "stake_ext create -net <net name> -addr_owner <addr> -token <ticker> -coins <value> -cert <name>\n"
	);

	return 1;
}

static dap_chain_datum_tx_receipt_t *s_external_stake_receipt_create(dap_hash_fast_t hash_burning_transaction, const char *token, uint256_t datoshi_burned)
{
	uint32_t l_ext_size = sizeof(dap_hash_fast_t) + dap_strlen(token) + 1;
	uint8_t *l_ext = DAP_NEW_S_SIZE(uint8_t, l_ext_size);
	memcpy(l_ext, &hash_burning_transaction, sizeof(dap_hash_fast_t));
	strcpy((char *)&l_ext[sizeof(dap_hash_fast_t)], token);
	dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
	dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID };
	dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, datoshi_burned,
																				 l_ext, l_ext_size);
	return l_receipt;
}

static int s_cli_srv_external_stake(int a_argc, char **a_argv, char **a_str_reply)
{
	enum {
		CMD_NONE, CMD_CREATE
	};

	int l_arg_index = 1;
	int l_cmd_num = CMD_NONE;

	if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "create", NULL)) {
		l_cmd_num = CMD_CREATE;
	}

	switch (l_cmd_num) {
		case CMD_CREATE:
			;
			return 1;
		default: {
			dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
			return -1;
		}
	}
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
