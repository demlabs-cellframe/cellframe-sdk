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

#ifndef _DAP_STREAM_CTL_H_
#define _DAP_STREAM_CTL_H_

#pragma once

#include "dap_config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"

#include "dap_stream.h"

#include "dap_enc.h"
#include "dap_enc_ks.h"
#include "dap_enc_http.h"
#include "dap_enc_key.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_events_socket.h"
#include "dap_http_simple.h"

#include "dap_stream_session.h"
#include "http_status_code.h"


typedef struct dap_http dap_http_t;
#define KEX_KEY_STR_SIZE 128

#ifdef __cplusplus
extern "C" {
#endif

int dap_stream_ctl_init();
void dap_stream_ctl_deinit();
void dap_stream_ctl_add_proc(struct dap_http * sh, const char * url);

#ifdef __cplusplus
}
#endif

#endif
