/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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





int dap_chain_wallet_cache_init();
int dap_chain_wallet_cache_deinit();


/**
 * @brief Find next transactions after l_tx_hash_curr for wallet addr and save pointer to datum into a_datum. If l_tx_hash_curr is NULL then function find first tx for addr.
 * @param a_net pointer to a net in which to find tx
 * @param a_addr wallet address
 * @param a_datum output parameter. Pointer for storaging pointer to current datum
 * @param a_tx_hash_curr current tx hash. Return hash of next tx that contained in a_datum and get start tx hash
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr, dap_chain_datum_t **a_datum, dap_hash_fast_t *a_tx_hash_curr);
