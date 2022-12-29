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
#include <stdio.h>
#include "dap_common.h"
#include "dap_config.h"

#include "avrs_content.h"
#include "avrs_ch.h"
#include "avrs_cli.h"
#include "avrs_srv.h"

#define LOG_TAG "avrestream"

#ifdef  DAP_SYS_DEBUG
    #ifndef DAP_VERSION
        #define DAP_VERSION 0.9-15
    #endif
#endif


int avrs_plugin_init(dap_config_t * a_config, char ** a_error_str)
{
    log_it(L_DEBUG, "AVReStream Plugin version %s --- loading ...", DAP_VERSION );

    avrs_content_init();
    avrs_ch_init();
    avrs_srv_init();
    avrs_cli_init();

#ifdef  DAP_SYS_DEBUG
    {
    pthread_t   l_tid;
    int         l_rc = 0;

    //l_rc = pthread_create(&l_tid, NULL, avrs_create_round_table, NULL);
    assert(!l_rc);
    }
#endif

    log_it(L_NOTICE, "AVReStream Plugin version %s loaded", DAP_VERSION );
    return 0;
}

void avrs_plugin_deinit()
{
    log_it(L_DEBUG, "AVReStream Plugin version %s --- cleanuping ...", DAP_VERSION );

    avrs_cli_deinit();
    avrs_srv_deinit();
    avrs_ch_deinit();
    avrs_content_deinit();

    log_it(L_NOTICE, "AVReStream Plugin unloaded");
}
