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
	dap_sign_t *l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt, l_receipt->size, 1);
	if (!l_sign)
		return false;
	dap_hash_fast_t l_pkey_hash;
	if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash))
		return false;
	return dap_hash_fast_compare(&l_pkey_hash, &a_cond->subtype.srv_pay.pkey_hash);

}
