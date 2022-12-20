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
#include <dap_stream_ch.h>
#include <dap_tsd.h>
#include "avrs_ch_pkt.h"
#include "avrs_cluster.h"

typedef struct avrs_session avrs_session_t;
typedef struct avrs_ch{
    dap_stream_ch_t * ch;
    avrs_session_t * session;

    void * _inheritor;
    byte_t _pvt[];
} avrs_ch_t;
#define AVRS_CH(a) ((avrs_ch_t *) ((a)->internal) )

typedef struct avrs_session_content avrs_session_content_t;
typedef int (*avrs_ch_pkt_content_callback_t)(avrs_ch_t *a_avrs_ch, avrs_session_content_t * a_content_session,
                                              avrs_ch_pkt_content_t * a_pkt, size_t a_pkt_data_size );

int avrs_ch_init(void);
void avrs_ch_deinit(void);

bool avrs_ch_tsd_sign_pkt_verify(avrs_ch_t * a_avrs_ch, dap_tsd_t * a_tsd_sign, size_t a_tsd_offset, const void * a_pkt, size_t a_pkt_hdr_size, size_t a_pkt_args_size);

int avrs_ch_pkt_in_content_add_callback(avrs_ch_pkt_content_callback_t a_callback);
