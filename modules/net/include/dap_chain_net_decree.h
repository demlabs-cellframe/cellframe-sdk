/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_datum_decree.h"
#include "dap_list.h"
#include "dap_chain_net.h"


typedef struct dap_chain_net_decree {
    dap_list_t *pkeys;
    uint16_t num_of_owners;
    uint16_t min_num_of_owners;
}   dap_chain_net_decree_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_net_decree_init(dap_chain_net_t *a_net);
int dap_chain_net_decree_deinit(dap_chain_net_t *a_net);

void dap_chain_net_decree_purge(dap_chain_net_t *a_net);

/**
 * @brief Apply (or record) a decree.
 * @param a_effective_ts the moment the decree becomes binding - the timestamp of the
 *        anchor that carried it, or of the decree datum itself; 0 means "now".
 *        Decree-controlled consensus parameters are era-dependent: a replay applies
 *        every decree before the main chain, and without this moment the parameters
 *        of the present would judge blocks of the past (Backbone block 144150).
 */
int dap_chain_net_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, bool a_anchored, uint64_t a_effective_ts);
int dap_chain_net_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash);
int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash);
dap_chain_datum_decree_t *dap_chain_net_decree_get_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash, bool *is_applied);
int dap_chain_net_decree_reset_applied(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_decree_hash);

// Number of decree datums accepted but not applied because this build does not
// recognize their type/subtype. They are kept so that a later build applies them
// without a chain scan.
uint64_t dap_chain_net_decree_unknown_count(void);

// Registers the decree journal snapshot section: the decree datums themselves,
// replayed through the normal load path on a snapshot-based start (see the
// section comment in dap_chain_net_decree.c).
int dap_chain_net_decree_journal_init(void);

#ifdef __cplusplus
}
#endif