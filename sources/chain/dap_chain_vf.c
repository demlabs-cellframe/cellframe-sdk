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

#include "dap_chain_vf.h"

#define LOG_TAG "dap_chain_vf"

/**
 * @brief dap_chain_vf_init
 * @return
 */
int dap_chain_vf_init()
{
    return 0;
}

/**
 * @brief dap_chain_vf_deinit
 */
void dap_chain_vf_deinit()
{

}

/**
 * @brief dap_chain_vf_add
 * @param a_vf_id
 * @param a_callback
 * @return
 */
int dap_chain_vf_add(dap_chain_vf_id_t a_vf_id, dap_chain_vf_callback_t a_callback)
{
    return 0;
}

/**
 * @brief dap_chain_vf_check
 * @param a_vf_id
 * @param a_ledger
 * @param a_receipt
 * @param a_arg
 * @param a_arg_size
 * @param a_param_value
 * @param a_param_value_size
 * @return
 */
bool dap_chain_vf_check(dap_chain_vf_id_t a_vf_id,  dap_ledger_t * a_ledger, dap_chain_datum_tx_receipt_t * a_receipt,
                        void *a_arg , size_t a_arg_size, const char * a_param_value, const char * a_param_value_size )
{
    return true;
}
