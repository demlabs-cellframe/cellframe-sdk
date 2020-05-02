/*
 * Authors:
 * Anatoliy Jurotich  <anatoliy.kurotich@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include "dap_client_remote.h"
#include "dap_server.h"

typedef void (*dap_traffic_callback_t) (dap_server_t *);

/**
 * @brief dap_traffic_track_init
 * @param clients
 * @param timeout callback
 */
void dap_traffic_track_init( dap_server_t *server, time_t timeout );

/**
 * @brief dap_traffic_track_deinit
 */
void dap_traffic_track_deinit( void );

/**
 * @brief dap_traffic_add_callback
 */
void dap_traffic_callback_set( dap_traffic_callback_t );

void dap_traffic_callback_stop( void );

