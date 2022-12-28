/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of AVReStream

 AVReStream is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 AVReStream is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any AVReStream based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include "avrs_ch.h"
#include "avrs_ch_pkt.h"

typedef int (*avrs_ch_pkt_session_callback_t)(avrs_ch_t *a_avrs_ch, avrs_session_t * a_session,
                                              avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size );


void avrs_ch_pkt_in_session(avrs_ch_t * a_avrs_ch,avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size);
int avrs_ch_pkt_in_session_add_callback(avrs_ch_pkt_session_callback_t a_callback);
