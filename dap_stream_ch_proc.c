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

#include "dap_common.h"
#include "dap_stream_ch_proc.h"


#define LOG_TAG "dap_stream_ch_proc"

stream_ch_proc_t proc[256]={0};

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
void stream_ch_proc_add(uint8_t id,stream_ch_callback_t new_callback,stream_ch_callback_t delete_callback,
                          stream_ch_callback_t packet_in_callback,
                          stream_ch_callback_t packet_out_callback
                          )
{
   proc[id].id=id;
   proc[id].new_callback=new_callback;
   proc[id].delete_callback=delete_callback;
   proc[id].packet_in_callback=packet_in_callback;
   proc[id].packet_out_callback=packet_out_callback;
}

/**
 * @brief stream_ch_proc_find
 * @param id
 * @return
 */
stream_ch_proc_t* stream_ch_proc_find(uint8_t id)
{
    return proc+id;
}
