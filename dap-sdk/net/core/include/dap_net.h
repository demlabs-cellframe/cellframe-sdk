/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2020
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

#include "dap_common.h"
#ifdef WIN32
// for Windows
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>

#define s6_addr32 s6_addr
#define herror perror
#else
// for Unix-like systems
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#endif

#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_proc_queue.h"
#include "dap_proc_thread.h"
#include "dap_server.h"
#include "dap_timerfd.h"
#include "dap_worker.h"

#include "dap_client.h"
#include "dap_client_http.h"
#include "dap_client_pool.h"

#include "dap_enc_http.h"
#include "dap_enc_ks.h"

#include "dap_http_client.h"
#include "dap_http_header.h"
#include "dap_http_user_agent.h"

#include "dap_http.h"
#include "dap_http_cache.h"
#include "dap_http_simple.h"
#include "http_status_code.h"

#include "dap_json_rpc.h"
#include "dap_json_rpc_errors.h"
#include "dap_json_rpc_notification.h"
#include "dap_json_rpc_params.h"
#include "dap_json_rpc_request.h"
#include "dap_json_rpc_request_handler.h"
#include "dap_json_rpc_response.h"
#include "dap_json_rpc_response_handler.h"

#include "dap_notify_srv.h"

#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"

#include "dap_stream.h"
#include "dap_stream_ctl.h"
#include "dap_stream_pkt.h"
#include "dap_stream_worker.h"

int dap_net_resolve_host(const char *a_host, int ai_family, struct sockaddr *a_addr_out);
