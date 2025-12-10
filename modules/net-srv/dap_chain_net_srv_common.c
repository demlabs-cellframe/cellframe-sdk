/*
 * Authors:
 * CellFrame Team <https://cellframe.net>
 * DeM Labs Inc.   <https://demlabs.net>
 *
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK
 *
 * CellFrame SDK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CellFrame SDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain_net_srv_common.h"

// These wrappers will be implemented by net module and registered via callbacks
// This way services don't depend on net, but net depends on net-srv

static dap_chain_id_t (*s_get_chain_id_by_name_callback)(dap_chain_net_id_t, const char *) = NULL;
static dap_chain_id_t (*s_get_chain_id_by_type_callback)(dap_chain_net_id_t, dap_chain_type_t) = NULL;
static dap_chain_net_id_t (*s_get_net_id_by_name_callback)(const char *) = NULL;

/**
 * @brief Register callbacks from net module
 * @details Called by net module during initialization
 */
void dap_chain_net_srv_set_net_callbacks(
    dap_chain_id_t (*a_get_chain_id_by_name)(dap_chain_net_id_t, const char *),
    dap_chain_id_t (*a_get_chain_id_by_type)(dap_chain_net_id_t, dap_chain_type_t),
    dap_chain_net_id_t (*a_get_net_id_by_name)(const char *)
)
{
    s_get_chain_id_by_name_callback = a_get_chain_id_by_name;
    s_get_chain_id_by_type_callback = a_get_chain_id_by_type;
    s_get_net_id_by_name_callback = a_get_net_id_by_name;
}

dap_chain_id_t dap_chain_net_srv_get_chain_id_by_name(dap_chain_net_id_t a_net_id, const char *a_chain_name)
{
    return s_get_chain_id_by_name_callback ? s_get_chain_id_by_name_callback(a_net_id, a_chain_name) : (dap_chain_id_t){.uint64 = 0};
}

dap_chain_id_t dap_chain_net_srv_get_chain_id_by_type(dap_chain_net_id_t a_net_id, dap_chain_type_t a_chain_type)
{
    return s_get_chain_id_by_type_callback ? s_get_chain_id_by_type_callback(a_net_id, a_chain_type) : (dap_chain_id_t){.uint64 = 0};
}

dap_chain_net_id_t dap_chain_net_srv_get_net_id_by_name(const char *a_net_name)
{
    return s_get_net_id_by_name_callback ? s_get_net_id_by_name_callback(a_net_name) : (dap_chain_net_id_t){.uint64 = 0};
}
