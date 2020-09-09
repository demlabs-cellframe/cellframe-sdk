/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _STREAM_CH_TYPE_H_
#define _STREAM_CH_TYPE_H_

#include <stdint.h>
#include "dap_stream_ch.h"


typedef struct dap_stream_ch_proc{
    uint8_t id; // Channel type id
    uint8_t enc_type; // Encryption type

    dap_stream_ch_callback_t new_callback;
    dap_stream_ch_callback_t delete_callback;

    dap_stream_ch_callback_t packet_in_callback;
    dap_stream_ch_callback_t packet_out_callback;
    void * internal;
} stream_ch_proc_t;

int stream_ch_proc_init();
void stream_ch_proc_deinit();

void dap_stream_ch_proc_add(uint8_t id,
                          dap_stream_ch_callback_t new_callback, dap_stream_ch_callback_t delete_callback,
                          dap_stream_ch_callback_t packet_in_callback,
                          dap_stream_ch_callback_t packet_out_callback
                          );
stream_ch_proc_t* stream_ch_proc_find(uint8_t id);

#endif
