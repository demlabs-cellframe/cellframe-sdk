/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2019-2025
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

#include "dap_json.h"
#include "dap_hash.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"
#include "dap_chain_common.h"

typedef struct dap_chain_net dap_chain_net_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_ledger_cli_init(void);
void dap_chain_ledger_cli_deinit(void);

dap_json_t *dap_db_history_tx(dap_json_t *a_json_arr_reply,
                              dap_hash_sha3_256_t *a_tx_hash,
                              dap_chain_t *a_chain,
                              const char *a_hash_out_type,
                              dap_ledger_t *a_ledger,
                              int a_version);

dap_json_t *dap_db_history_addr(dap_json_t *a_json_arr_reply,
                                dap_chain_addr_t *a_addr,
                                dap_chain_t *a_chain,
                                dap_ledger_t *a_ledger,
                                const char *a_hash_out_type,
                                const char *a_addr_str,
                                dap_json_t *a_json_obj_summary,
                                size_t a_limit, size_t a_offset,
                                bool a_brief, const char *a_srv,
                                dap_chain_tx_tag_action_type_t a_action,
                                bool a_head, int a_version);

dap_json_t *dap_db_history_tx_all(dap_json_t *a_json_arr_reply,
                                  dap_chain_t *a_chain,
                                  dap_ledger_t *a_ledger,
                                  const char *a_hash_out_type,
                                  dap_json_t *a_json_obj_summary,
                                  size_t a_limit, size_t a_offset,
                                  bool a_brief, const char *a_srv,
                                  dap_chain_tx_tag_action_type_t a_action,
                                  bool a_head, int a_version);

#ifdef __cplusplus
}
#endif

