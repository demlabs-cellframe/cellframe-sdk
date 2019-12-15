/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <stdint.h>
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out.h"

typedef uint64_t dap_chain_vf_id_t;
typedef bool (*dap_chain_vf_callback_t) (dap_ledger_t *, dap_chain_datum_tx_receipt_t*, void * ,size_t  );



// Verificator TX_CHECK argument structure
typedef struct dap_chain_vf_tx_check {
    dap_chain_hash_fast_t tx_hash; // Transaction hash that should exists, if not null
    uint64_t value;     // Total tx value that should be exactly same, if not null
    uint64_t value_max; // Total tx value not more or equal, if not null
    uint64_t value_min; // Total tx value not less or equal, if not null
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX]; // Tocken ticker is exactly same, if not null
} dap_chain_vf_tx_check_t;

typedef struct dap_chain_vf_tx_cond_in_check {
    /// General TX check
    dap_chain_vf_tx_check_t tx_check;
    /// If any field is not null it must be equal to receipt info in the input item.
    /// Checks first input. TODO: make able to check more than one inputs and input receipts
    dap_chain_receipt_info_t receipt_info;
} dap_chain_vf_tx_cond_in_check_t;


typedef struct dap_chain_vf_tx_cond_out_srv_pay_check {
    /// Do the general tx checks if some of them are not null
    dap_chain_vf_tx_check_t tx_check;
    /// Check if public key hash its not null
    dap_chain_hash_fast_t pkey_hash;
    /// Check for service uid if its not null
    dap_chain_net_srv_uid_t srv_uid;
    /// Check for units if not null
    dap_chain_net_srv_price_unit_uid_t unit;
    /// Check for maximum price per unit if not null
    uint64_t unit_price_max_datoshi;
     /// Chek if params are exactly
    uint32_t params_size;
} dap_chain_vf_tx_cond_out_check_t;


///              General usage verificators IDs

#define         DAP_CHAIN_VF_ID_TX_CHECK                            0x0000000000000010
#define         DAP_CHAIN_VF_ID_TX_IN_COND_CHECK                    0x0000000000000020
#define         DAP_CHAIN_VF_ID_TX_OUT_COND_SRV_PAY_CHECK           0x0000000000000030

#ifdef __cplusplus
extern "C" {
#endif

// Init general usage verificators
int dap_chain_vf_init();
void dap_chain_vf_deinit();

// Add custom verificator
int dap_chain_vf_add(dap_chain_vf_id_t a_vf_id, dap_chain_vf_callback_t a_callback);

// Check if verificator pass receipt
bool dap_chain_vf_check(dap_chain_vf_id_t a_vf_id,  dap_ledger_t * a_ledger, dap_chain_datum_tx_receipt_t * a_receipt,
                        void *a_arg , size_t a_arg_size, const char * a_param_value, const char * a_param_value_size );

#ifdef __cplusplus
}
#endif
