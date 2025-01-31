/*
* Authors:
* Pavel Uhanov <pavel.uhanov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2025
* All rights reserved.

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

#include "dap_common.h"

#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS            1
#define DAP_CHAIN_POLICY_FLAG_DEACTIVATE_BY_TS          1 << 1
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM     1 << 2
#define DAP_CHAIN_POLICY_FLAG_DEACTIVATE_BY_BLOCK_NUM   1 << 3
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_CONFIG        1 << 4
#define DAP_CHAIN_POLICY_FLAG_DEACTIVATE_BY_CONFIG      1 << 5

int dap_chain_policy_init();
int dap_chain_policy_net_add(dap_chain_net_id_t a_net_id);