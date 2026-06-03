/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
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


#include "dap_common.h"
#include "dap_chain_datum_hashtree_roots.h"
#include "dap_serialize.h"
#include <stddef.h>

#define LOG_TAG "dap_chain_datum_hashtree_roots"

const dap_serialize_field_t g_dap_chain_datum_hashtree_roots_v2_fields[] = {
    {
        .name = "main",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_datum_hashtree_roots_v2_mem_t, main),
        .size = sizeof(((dap_chain_datum_hashtree_roots_v2_mem_t *)0)->main),
    },
    {
        .name = "txs",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_datum_hashtree_roots_v2_mem_t, txs),
        .size = sizeof(((dap_chain_datum_hashtree_roots_v2_mem_t *)0)->txs),
    },
};

const size_t g_dap_chain_datum_hashtree_roots_v2_field_count =
    sizeof(g_dap_chain_datum_hashtree_roots_v2_fields) / sizeof(g_dap_chain_datum_hashtree_roots_v2_fields[0]);

const dap_serialize_schema_t g_dap_chain_datum_hashtree_roots_v2_schema = {
    .name = "chain_datum_hashtree_roots_v2",
    .version = 1,
    .struct_size = sizeof(dap_chain_datum_hashtree_roots_v2_mem_t),
    .field_count = sizeof(g_dap_chain_datum_hashtree_roots_v2_fields) / sizeof(g_dap_chain_datum_hashtree_roots_v2_fields[0]),
    .fields = g_dap_chain_datum_hashtree_roots_v2_fields,
    .magic = DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_SERIALIZE_MAGIC,
    .validate_func = NULL,
};
