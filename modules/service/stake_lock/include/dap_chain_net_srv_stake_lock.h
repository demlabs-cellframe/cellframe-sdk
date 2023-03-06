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
#include <json.h>

#define DAP_CHAIN_NET_SRV_STAKE_LOCK_ID 0x12

/**
 * @brief The cond_params struct thats placed in tx_cond->params[] section
 */


int 					dap_chain_net_srv_stake_lock_init(void);
void					dap_chain_net_srv_stake_lock_deinit(void);

// Create stake lock datum
dap_chain_datum_t *dap_chain_net_srv_stake_lock_datum_create(dap_chain_net_t *a_net,
                                                   dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                                   const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                   uint256_t a_value, uint256_t a_value_fee, dap_chain_net_srv_uid_t a_srv_uid,
                                                   dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                   bool a_create_base_tx,uint256_t *a_value_change, uint32_t *a_tx_out_prev_idx);
// Burning_tx_create
dap_chain_datum_t *dap_chain_burning_tx_create(dap_chain_t* a_chain, dap_enc_key_t* a_key_from,
                                                    const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
                                                    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                    uint256_t a_value,uint256_t a_value_fee,uint32_t *a_tx_out_prev_idx,uint256_t *a_value_change);
