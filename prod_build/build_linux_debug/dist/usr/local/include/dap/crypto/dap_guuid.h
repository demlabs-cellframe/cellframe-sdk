/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_common.h"
#include "dap_uuid.h"
#include "dap_math_ops.h"

typedef union dap_guuid {
    struct {
        uint64_t net_id;
        uint64_t srv_id;
    } DAP_ALIGN_PACKED;
    uint128_t raw;
} DAP_ALIGN_PACKED dap_guuid_t;

typedef union dap_guuid_str {
    const char s[ 2 * sizeof(uint128_t) + 3 ];
} dap_guuid_str_t;

static inline dap_guuid_t dap_guuid_new()
{
    uint128_t l_ret = dap_uuid_generate_uint128();
    return *(dap_guuid_t *)&l_ret;
}

DAP_STATIC_INLINE dap_guuid_t dap_guuid_compose(uint64_t a_net_id, uint64_t a_service_id)
{
    return (dap_guuid_t){{ .net_id = a_net_id, .srv_id = a_service_id }};
}
dap_guuid_str_t dap_guuid_to_hex_str_(dap_guuid_t a_guuid);
#define dap_guuid_to_hex_str(guid) dap_guuid_to_hex_str_(guid).s
dap_guuid_t dap_guuid_from_hex_str(const char *a_hex_str, bool *success);
