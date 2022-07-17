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
	uint32_t l_ext_size = sizeof(dap_hash_fast_t) + DAP_CHAIN_TICKER_SIZE_MAX;
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
	/*if (!a_owner)
		return false;*/
	dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t *)
			dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_RECEIPT, NULL);
	if (!l_receipt)
		return false;

	dap_hash_fast_t hash_burning_transaction;
	char ticker[DAP_CHAIN_TICKER_SIZE_MAX + 1];
	memset(ticker, 0, sizeof(ticker));
	if (l_receipt->exts_size) {
		memcpy(&hash_burning_transaction, l_receipt->exts_n_signs, sizeof(dap_hash_fast_t));
		memcpy(&ticker, &l_receipt->exts_n_signs[sizeof(dap_hash_fast_t)], l_receipt->exts_size - sizeof(dap_hash_fast_t));
	}
	else
		return false;

	if (dap_hash_fast_is_blank(&hash_burning_transaction))
		return false;

//	dap_chain_ledger_tx_item_t *l_item_out = NULL;
//	dap_chain_datum_tx_t *l_tx_prev =
//			s_find_datum_tx_by_hash(a_ledger, &l_tx_prev_hash, &l_item_out);

	return true;

}
