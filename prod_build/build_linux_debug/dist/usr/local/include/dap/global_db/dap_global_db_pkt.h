/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
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

#include "dap_time.h"
#include "dap_global_db_driver.h"

#define DAP_GLOBAL_DB_WRITE_SERIALIZED
#define DAP_GLOBAL_DB_PKT_PACK_MAX_COUNT            1024

typedef struct dap_global_db_pkt {
    uint64_t crc;   // Must be first for compute
    dap_nanotime_t timestamp;
    uint16_t group_len;
    uint16_t key_len;
    uint32_t value_len;
    uint32_t data_len;
    uint8_t flags;
    byte_t data[];
} DAP_ALIGN_PACKED dap_global_db_pkt_t;

DAP_STATIC_INLINE uint32_t dap_global_db_pkt_get_size(dap_global_db_pkt_t *a_pkt)
{
    return (uint32_t)sizeof(*a_pkt) + a_pkt->data_len > a_pkt->data_len ? (uint32_t)sizeof(*a_pkt) + a_pkt->data_len : 0;
}

typedef struct dap_global_db_pkt_pack {
    uint64_t data_size;
    uint32_t obj_count;
    byte_t data[];
} DAP_ALIGN_PACKED dap_global_db_pkt_pack_t;

DAP_STATIC_INLINE uint64_t dap_global_db_pkt_pack_get_size(dap_global_db_pkt_pack_t *a_pkt_pack)
{
    return (uint64_t)sizeof(*a_pkt_pack) + a_pkt_pack->data_size > a_pkt_pack->data_size ? (uint64_t)sizeof(*a_pkt_pack) + a_pkt_pack->data_size : 0;
}

typedef struct dap_global_db_hash_pkt {
    uint32_t hashes_count;
    uint16_t group_name_len;
    byte_t group_n_hashses[];
} DAP_ALIGN_PACKED dap_global_db_hash_pkt_t;

DAP_STATIC_INLINE uint64_t dap_global_db_hash_pkt_get_size(dap_global_db_hash_pkt_t *a_hash_pkt)
{
    if (a_hash_pkt->hashes_count >= UINT32_MAX / sizeof(dap_global_db_driver_hash_t))
        return 0;
    return (uint64_t)sizeof(dap_global_db_hash_pkt_t) + a_hash_pkt->group_name_len + a_hash_pkt->hashes_count * sizeof(dap_global_db_driver_hash_t);
}

typedef struct dap_global_db_start_pkt {
    dap_global_db_driver_hash_t last_hash;
    uint16_t group_len;
    byte_t group[];
} DAP_ALIGN_PACKED dap_global_db_start_pkt_t;

DAP_STATIC_INLINE uint32_t dap_global_db_start_pkt_get_size(dap_global_db_start_pkt_t *a_start_pkt)
{
    return (uint32_t)sizeof(dap_global_db_start_pkt_t) + a_start_pkt->group_len;
}

dap_global_db_pkt_pack_t *dap_global_db_pkt_pack(dap_global_db_pkt_pack_t *a_old_pkt, dap_global_db_pkt_t *a_new_pkt);
dap_global_db_pkt_t *dap_global_db_pkt_serialize(dap_store_obj_t *a_store_obj);
#ifdef DAP_GLOBAL_DB_WRITE_SERIALIZED
dap_store_obj_t *dap_global_db_pkt_pack_deserialize(dap_global_db_pkt_pack_t *a_pkt, size_t *a_store_obj_count);
#else
dap_store_obj_t **dap_global_db_pkt_pack_deserialize(dap_global_db_pkt_pack_t *a_pkt, size_t *a_store_obj_count, dap_stream_node_addr_t *a_addr);
#endif
dap_store_obj_t *dap_global_db_pkt_deserialize(dap_global_db_pkt_t *a_pkt, size_t a_pkt_size, dap_stream_node_addr_t *a_addr);
dap_sign_t *dap_store_obj_sign(dap_store_obj_t *a_obj, dap_enc_key_t *a_key, uint64_t *a_checksum);
DAP_STATIC_INLINE uint64_t dap_store_obj_checksum(dap_store_obj_t *a_obj)
{
    uint64_t ret = 0;
    dap_store_obj_sign(a_obj, NULL, &ret);
    return ret;
}

bool dap_global_db_pkt_check_sign_crc(dap_store_obj_t *a_obj);
void *dap_gossip_pkt_read(dap_hash_fast_t *a_route, size_t *a_route_len);
