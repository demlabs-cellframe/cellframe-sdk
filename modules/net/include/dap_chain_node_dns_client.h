/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * Dmitriy Gerasimov <dmitriy.gerasmiov@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DapChain SDK the open source project

    DapChain SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DapChain SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DapChain SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdint.h>
#include "dap_worker.h"
#include "dap_chain_node.h"

#define DNS_LISTEN_PORT 53      // UDP

typedef struct _dap_dns_buf_t {
    char *data;
    uint32_t size;
} dap_dns_buf_t;

// node info request callbacks
typedef void (*dap_dns_client_node_info_request_success_callback_t) (dap_worker_t * a_worker, dap_chain_node_info_t * , void *);
typedef void (*dap_dns_client_node_info_request_error_callback_t) (dap_worker_t * a_worker, dap_chain_node_info_t * , void *, int);

void dap_chain_node_info_dns_request(struct in_addr a_addr, uint16_t a_port, char *a_name, dap_chain_node_info_t *a_result,
                           dap_dns_client_node_info_request_success_callback_t a_callback_success,
                           dap_dns_client_node_info_request_error_callback_t a_callback_error,void * a_callback_arg);

dap_chain_node_info_t *dap_dns_resolve_hostname(char *str);

void dap_dns_buf_init(dap_dns_buf_t *buf, char *msg);
void dap_dns_buf_put_uint64(dap_dns_buf_t *buf, uint64_t val);
void dap_dns_buf_put_uint32(dap_dns_buf_t *buf, uint32_t val);
void dap_dns_buf_put_uint16(dap_dns_buf_t *buf, uint16_t val);
uint16_t dap_dns_buf_get_uint16(dap_dns_buf_t *buf);
