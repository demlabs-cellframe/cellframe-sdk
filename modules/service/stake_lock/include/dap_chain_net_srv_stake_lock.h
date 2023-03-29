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

#pragma once

#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "json.h"

#define DAP_CHAIN_NET_SRV_STAKE_LOCK_ID 0x12

// Allow to spend stake by network
// Need for service staking to enable network governance to fee the service provider
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_ENABLE_NET_FEE			0x00000001
// Delegate token to prove thats stake is provided
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_DELEGATE_TOKEN			0x00000002
// Delegate public key's hash
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_DELEGATE_PKEY				0x00000004
// Lock by time
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME					0x00000008
// Create base tx for delegated token
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX			0x00000010

/**
 * @brief The cond_params struct thats placed in tx_cond->params[] section
 */
int 					dap_chain_net_srv_stake_lock_init(void);
void					dap_chain_net_srv_stake_lock_deinit(void);

// Create cond out
dap_chain_tx_out_cond_t	*dap_chain_net_srv_stake_lock_create_cond_out(dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                                    uint64_t a_time_staking, uint256_t a_reinvest_percent, bool create_base_tx);

json_object *dap_chain_net_srv_stake_lock_cond_out_to_json(dap_chain_tx_out_cond_t *a_stake_lock);

// Create mempool
dap_chain_hash_fast_t	*dap_chain_net_srv_stake_lock_mempool_create(dap_chain_net_t *a_net,
                                                                       dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                                                       const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                                       uint256_t a_value, dap_chain_net_srv_uid_t a_srv_uid,
                                                                       dap_chain_addr_t *a_addr_holder, dap_chain_t *a_chain,
                                                                       uint64_t a_time_staking, uint256_t a_reinvest_percent,
                                                                       bool create_base_tx);

// Burning_tx_create
dap_chain_datum_t		*dap_chain_burning_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
											   const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
											   const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
											   uint256_t a_value);
