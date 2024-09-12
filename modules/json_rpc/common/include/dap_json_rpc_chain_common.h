/*
 * Authors:
 * Alexey V. Stratulat <alexey.stratulat@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2023
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#include "dap_chain_common.h"
#include "dap_json_rpc_errors.h"

json_object *dap_chain_addr_to_json(const dap_chain_addr_t *a_addr);

DAP_STATIC_INLINE json_object *dap_chain_net_id_to_json(dap_chain_net_id_t a_net_id) {
    return json_object_new_uint64(a_net_id.uint64);
}
