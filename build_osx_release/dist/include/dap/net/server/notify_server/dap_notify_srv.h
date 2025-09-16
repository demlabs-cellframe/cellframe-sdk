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
#include <stdint.h>

#include "dap_common.h"

int dap_notify_server_init();
void dap_notify_server_deinit();
DAP_PRINTF_ATTR(2, 3) int dap_notify_server_send_f_inter(uint32_t a_worker_id, const char *a_format, ...);
int dap_notify_server_send_mt(const char * a_data);
DAP_PRINTF_ATTR(1, 2) int dap_notify_server_send_f_mt(const char *a_format, ...);

typedef bool (*dap_notify_data_user_callback_t)(const char *data);
void dap_notify_data_set_user_callback(dap_notify_data_user_callback_t a_cb);

void dap_notify_srv_set_callback_new(dap_events_socket_callback_t a_cb);
