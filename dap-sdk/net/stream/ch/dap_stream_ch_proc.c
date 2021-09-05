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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_stream_ch_proc.h"


#define LOG_TAG "dap_stream_ch_proc"

static stream_ch_proc_t s_proc[256]={{0}};

/**
 * @brief stream_ch_type_init Initialize stream channels type module
 * @return  0 if ok others if no
 */
int stream_ch_proc_init()
{
    log_it(L_NOTICE, "Module stream channel types initialized");
    return 0;
}

void stream_ch_proc_deinit()
{

}


/**
 * @brief stream_ch_proc_add
 * @param id
 * @param delete_callback
 * @param packet_in_callback
 * @param packet_out_callback
 */
void dap_stream_ch_proc_add(uint8_t id,dap_stream_ch_callback_t new_callback,dap_stream_ch_callback_t delete_callback,
                          dap_stream_ch_callback_t packet_in_callback,
                          dap_stream_ch_callback_t packet_out_callback
                          )
{
   s_proc[id].id=id;
   s_proc[id].new_callback=new_callback;
   s_proc[id].delete_callback=delete_callback;
   s_proc[id].packet_in_callback=packet_in_callback;
   s_proc[id].packet_out_callback=packet_out_callback;
}

/**
 * @brief stream_ch_proc_find
 * @param id
 * @return
 */
stream_ch_proc_t* dap_stream_ch_proc_find(uint8_t id)
{
    return s_proc+id;
}
