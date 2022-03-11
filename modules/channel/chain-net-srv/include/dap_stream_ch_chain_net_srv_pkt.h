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

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "dap_chain_net_srv_stream_session.h"


size_t dap_stream_ch_chain_net_srv_pkt_data_write(dap_stream_ch_t *a_ch,
                                                  dap_chain_net_srv_uid_t a_srv_uid, uint32_t a_usage_id  ,
                                                  const void * a_data, size_t a_data_size);

size_t dap_stream_ch_chain_net_srv_pkt_data_write_f(dap_stream_ch_t *a_ch, dap_chain_net_srv_uid_t a_srv_uid, uint32_t a_usage_id,
                                                    const char *a_str, ...);
