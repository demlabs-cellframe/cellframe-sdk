/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Aleksandr Lysikov <alexander.lysikov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
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

#include "dap_config.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_stream_session.h"

typedef struct dap_chain_net_srv dap_chain_net_srv_t;

typedef void (*dap_chain_net_srv_callback_t)(dap_chain_net_srv_t *, dap_chain_net_srv_client_t *);
typedef int (*dap_chain_net_srv_callback_data_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_t *, const void *, size_t );

typedef struct dap_chain_net_srv
{
    dap_chain_net_srv_uid_t uid; // Unique ID for service.
    dap_chain_net_srv_abstract_t srv_common;
    dap_chain_net_srv_price_t *pricelist;
    dap_chain_callback_trafic_t callback_trafic;
    dap_chain_net_srv_callback_data_t callback_requested;
    dap_chain_net_srv_callback_data_t callback_receipt_first_success;
    dap_chain_net_srv_callback_data_t callback_response_error;
    dap_chain_net_srv_callback_data_t callback_receipt_next_success;
    void * _inhertor;
} dap_chain_net_srv_t;
typedef void (*dap_chain_net_srv_callback_new_t)(dap_chain_net_srv_t *, dap_config_t *);


int dap_chain_net_srv_init(dap_config_t * a_cfg);
void dap_chain_net_srv_deinit(void);
dap_chain_net_srv_t* dap_chain_net_srv_add(dap_chain_net_srv_uid_t a_uid,dap_chain_net_srv_callback_data_t a_callback_requested,
                                           dap_chain_net_srv_callback_data_t a_callback_response_success,
                                           dap_chain_net_srv_callback_data_t a_callback_response_error,
                                           dap_chain_net_srv_callback_data_t a_callback_receipt_next_success
                                           );
void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del_all(void);
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid);
size_t dap_chain_net_srv_count(void);
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void);
dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                dap_chain_net_srv_usage_t * a_usage,
                dap_chain_net_srv_price_t * a_price, const void * a_ext, size_t a_ext_size
                );

