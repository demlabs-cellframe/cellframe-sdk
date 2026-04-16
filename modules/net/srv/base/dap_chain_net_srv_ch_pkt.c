/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* Demlabs Limited   https://demlabs.net
* Copyright  (c) 2017-2020
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

#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dap_stream.h>
#include <dap_common.h>
#include <dap_stream_pkt.h>
#include <dap_stream_ch_pkt.h>
#include "dap_chain_net_srv_ch_pkt.h"
#include "dap_serialize.h"

#define LOG_TAG "dap_chain_net_srv_ch_pkt"


size_t dap_chain_net_srv_ch_pkt_data_write(dap_stream_ch_t *a_ch,
                                                  dap_chain_srv_uid_t a_srv_uid, uint32_t a_usage_id  ,
                                                  const void * a_data, size_t a_data_size)
{
    dap_chain_net_srv_ch_pkt_data_t  * l_pkt_data;
    size_t l_pkt_data_size = sizeof (l_pkt_data->hdr) + a_data_size;
    l_pkt_data = DAP_NEW_Z_SIZE(dap_chain_net_srv_ch_pkt_data_t, l_pkt_data_size );
    l_pkt_data->hdr.version = 1;
    l_pkt_data->hdr.srv_uid = a_srv_uid;
    l_pkt_data->hdr.usage_id = a_usage_id;
    memcpy( l_pkt_data->data, a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA , l_pkt_data, l_pkt_data_size);
    DAP_DELETE(l_pkt_data);
    return l_ret;
}

/**
 * @brief dap_chain_net_ch_pkt_write_f
 * @param a_ch
 * @param a_type
 * @param a_net_id
 * @param a_str
 * @return
 */
size_t dap_chain_net_srv_ch_pkt_data_write_f(dap_stream_ch_t *a_ch, dap_chain_srv_uid_t a_srv_uid, uint32_t a_usage_id, const char *a_str, ...)
{

    va_list ap, ap_copy;
    va_start(ap, a_str);
    va_copy(ap_copy, ap);
    size_t l_buf_size = vsnprintf(NULL, 0, a_str, ap);
    va_end(ap);

    l_buf_size++; // include trailing 0
    char *l_buf = DAP_NEW_Z_SIZE(char, l_buf_size);
    vsnprintf(l_buf, l_buf_size, a_str, ap_copy);
    va_end(ap_copy);
    size_t ret = dap_chain_net_srv_ch_pkt_data_write(a_ch, a_srv_uid, a_usage_id, l_buf, l_buf_size);
    DAP_DELETE(l_buf);
    return ret;
}

const dap_serialize_field_t g_dap_chain_net_srv_ch_pkt_request_hdr_fields[] = {
    { .name = "net_id", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, net_id), .size = DAP_CHAIN_NET_ID_SIZE },
    { .name = "tx_cond", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, tx_cond), .size = DAP_HASH_SHA3_256_SIZE },
    { .name = "srv_uid", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, srv_uid), .size = DAP_CHAIN_NET_SRV_UID_SIZE },
    { .name = "token", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, token), .size = DAP_CHAIN_TICKER_SIZE_MAX },
    { .name = "client_pkey_hash", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, client_pkey_hash), .size = DAP_HASH_SHA3_256_SIZE },
    { .name = "order_hash", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t, order_hash), .size = DAP_HASH_SHA3_256_SIZE },
};

const dap_serialize_schema_t g_dap_chain_net_srv_ch_pkt_request_hdr_schema = {
    .name = "chain_net_srv_ch_pkt_request_hdr",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_srv_ch_pkt_request_hdr_mem_t),
    .field_count = sizeof(g_dap_chain_net_srv_ch_pkt_request_hdr_fields) /
                   sizeof(g_dap_chain_net_srv_ch_pkt_request_hdr_fields[0]),
    .fields = g_dap_chain_net_srv_ch_pkt_request_hdr_fields,
    .magic = DAP_CHAIN_NET_SRV_CH_PKT_REQUEST_HDR_MAGIC,
    .validate_func = NULL,
};

const dap_serialize_field_t g_dap_chain_net_srv_ch_pkt_data_hdr_fields[] = {
    { .name = "wire", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_data_hdr_mem_t, bytes), .size = DAP_CHAIN_NET_SRV_CH_PKT_DATA_HDR_WIRE_SIZE },
};

const dap_serialize_schema_t g_dap_chain_net_srv_ch_pkt_data_hdr_schema = {
    .name = "chain_net_srv_ch_pkt_data_hdr",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_srv_ch_pkt_data_hdr_mem_t),
    .field_count = sizeof(g_dap_chain_net_srv_ch_pkt_data_hdr_fields) /
                   sizeof(g_dap_chain_net_srv_ch_pkt_data_hdr_fields[0]),
    .fields = g_dap_chain_net_srv_ch_pkt_data_hdr_fields,
    .magic = DAP_CHAIN_NET_SRV_CH_PKT_DATA_HDR_MAGIC,
    .validate_func = NULL,
};

const dap_serialize_field_t g_dap_chain_net_srv_ch_pkt_success_hdr_fields[] = {
    { .name = "usage_id", .type = DAP_SERIALIZE_TYPE_UINT32, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_success_hdr_mem_t, usage_id), .size = sizeof(uint32_t) },
    { .name = "net_id", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_success_hdr_mem_t, net_id), .size = DAP_CHAIN_NET_ID_SIZE },
    { .name = "srv_uid", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_success_hdr_mem_t, srv_uid), .size = DAP_CHAIN_NET_SRV_UID_SIZE },
};

const dap_serialize_schema_t g_dap_chain_net_srv_ch_pkt_success_hdr_schema = {
    .name = "chain_net_srv_ch_pkt_success_hdr",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_srv_ch_pkt_success_hdr_mem_t),
    .field_count = sizeof(g_dap_chain_net_srv_ch_pkt_success_hdr_fields) /
                   sizeof(g_dap_chain_net_srv_ch_pkt_success_hdr_fields[0]),
    .fields = g_dap_chain_net_srv_ch_pkt_success_hdr_fields,
    .magic = DAP_CHAIN_NET_SRV_CH_PKT_SUCCESS_HDR_MAGIC,
    .validate_func = NULL,
};

const dap_serialize_field_t g_dap_chain_net_srv_ch_pkt_error_fields[] = {
    { .name = "net_id", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_error_mem_t, net_id), .size = DAP_CHAIN_NET_ID_SIZE },
    { .name = "srv_uid", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_error_mem_t, srv_uid), .size = DAP_CHAIN_NET_SRV_UID_SIZE },
    { .name = "usage_id", .type = DAP_SERIALIZE_TYPE_UINT32, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_error_mem_t, usage_id), .size = sizeof(uint32_t) },
    { .name = "code", .type = DAP_SERIALIZE_TYPE_UINT32, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_error_mem_t, code), .size = sizeof(uint32_t) },
};

const dap_serialize_schema_t g_dap_chain_net_srv_ch_pkt_error_schema = {
    .name = "chain_net_srv_ch_pkt_error",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_srv_ch_pkt_error_mem_t),
    .field_count = sizeof(g_dap_chain_net_srv_ch_pkt_error_fields) /
                   sizeof(g_dap_chain_net_srv_ch_pkt_error_fields[0]),
    .fields = g_dap_chain_net_srv_ch_pkt_error_fields,
    .magic = DAP_CHAIN_NET_SRV_CH_PKT_ERROR_MAGIC,
    .validate_func = NULL,
};

const dap_serialize_field_t g_dap_chain_net_srv_ch_pkt_test_fixed_fields[] = {
    { .name = "fixed", .type = DAP_SERIALIZE_TYPE_BYTES_FIXED, .flags = DAP_SERIALIZE_FLAG_NONE,
      .offset = offsetof(dap_chain_net_srv_ch_pkt_test_fixed_mem_t, bytes), .size = DAP_CHAIN_NET_SRV_CH_PKT_TEST_FIXED_WIRE_SIZE },
};

const dap_serialize_schema_t g_dap_chain_net_srv_ch_pkt_test_fixed_schema = {
    .name = "chain_net_srv_ch_pkt_test_fixed",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_srv_ch_pkt_test_fixed_mem_t),
    .field_count = sizeof(g_dap_chain_net_srv_ch_pkt_test_fixed_fields) /
                   sizeof(g_dap_chain_net_srv_ch_pkt_test_fixed_fields[0]),
    .fields = g_dap_chain_net_srv_ch_pkt_test_fixed_fields,
    .magic = DAP_CHAIN_NET_SRV_CH_PKT_TEST_FIXED_MAGIC,
    .validate_func = NULL,
};
