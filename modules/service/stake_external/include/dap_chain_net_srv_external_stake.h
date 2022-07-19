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

#pragma once

#include "dap_chain_net_srv_stake.h"

#define DAP_CHAIN_NET_SRV_EXTERNAL_STAKE_ID 0x12

typedef enum external_stake_error_code {
	NO_ERROR 				= 0,
	NET_ARG_ERROR			= 1,
	NET_ERROR				= 2,
	TOKEN_ARG_ERROR 		= 3,
	TOKEN_ERROR				= 4,
	COINS_ARG_ERROR			= 5,
	COINS_FORMAT_ERROR		= 6,
	ADDR_ARG_ERROR			= 7,
	ADDR_FORMAT_ERROR		= 8,
	CERT_ARG_ERROR			= 9,
	CERT_LOAD_ERROR			= 10,
	CHAIN_ERROR				= 11,
	CHAIN_EMISSION_ERROR	= 12,
	MONTHS_ERROR			= 13
} error_code;

bool	dap_chain_net_srv_stake_lock_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner);
bool	dap_chain_net_srv_external_stake_init(void);

