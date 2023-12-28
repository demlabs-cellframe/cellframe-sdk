/*
 * Authors:
 * Alexey V. Stratulat <alexey.stratulat@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2023
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

#include "dap_chain_datum_tx_items.h"
#include "dap_json_rpc_errors.h"


json_object *dap_chain_datum_tx_item_in_ems_to_json(const dap_chain_tx_in_ems_t *a_in_ems);
json_object* dap_chain_datum_tx_item_in_to_json(dap_chain_tx_in_t *a_in);
json_object* dap_chain_datum_tx_item_tsd_to_json(dap_chain_tx_tsd_t *a_tsd);
json_object* dap_chain_datum_tx_item_in_cond_to_json(dap_chain_tx_in_cond_t *a_in_cond);
json_object* dap_chain_datum_tx_item_out_to_json(const dap_chain_tx_out_t *a_out);
json_object* dap_chain_datum_tx_item_out_ext_to_json(const dap_chain_tx_out_ext_t *a_out_ext);
json_object *dap_chain_datum_tx_item_out_cond_fee_to_json(dap_chain_tx_out_cond_t *a_fee);
json_object *dap_chain_datum_tx_item_out_cond_srv_pay_to_json(dap_chain_tx_out_cond_t *item);
json_object* dap_chain_datum_tx_item_out_cond_srv_xchange_to_json(dap_chain_tx_out_cond_t* a_srv_xchange);
json_object *dap_chain_datum_tx_item_out_cond_srv_stake_to_json(dap_chain_tx_out_cond_t* a_srv_stake);
json_object *dap_chain_net_srv_stake_lock_cond_out_to_json(dap_chain_tx_out_cond_t *a_stake_lock);
json_object* dap_chain_datum_tx_item_sig_to_json(const dap_chain_tx_sig_t *a_sig);
