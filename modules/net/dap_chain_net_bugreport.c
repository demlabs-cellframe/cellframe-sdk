/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2020
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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"

#include "http_status_code.h"
#include "dap_http_simple.h"
#include "dap_enc_http.h"
#include "dap_chain_net_bugreport.h"

#define LOG_TAG "chain_net_bugreport"

#define BUGREPORT_URL "/bugreport"

static int bugreport_write_to_file(byte_t *a_request_byte, size_t a_request_size)
{
    int l_ret = -2;
    if(!a_request_byte || !a_request_size)
        return -1;
    char *l_dir_str = dap_strdup_printf("%s/var/bugreport", g_sys_dir_path);
    dap_mkdir_with_parents(l_dir_str);

    const time_t l_timer = time(NULL);
    struct tm l_tm;
    localtime_r(&l_timer, &l_tm);
    char *l_filename_str = dap_strdup_printf("%s/%02d-%02d-%02d_%02d:%02d:%02d.brt", l_dir_str,
            l_tm.tm_year - 100, l_tm.tm_mon, l_tm.tm_mday,
            l_tm.tm_hour, l_tm.tm_min, l_tm.tm_sec);
    FILE *l_fp;
    if((l_fp = fopen(l_filename_str, "wb")) != NULL) {
        if(fwrite(a_request_byte, 1, a_request_size, l_fp) == a_request_size)
            l_ret = 0;
        else
            l_ret = -3;
        fclose(l_fp);
    }
    DAP_DELETE(l_filename_str);
    DAP_DELETE(l_dir_str);
    return l_ret;
}

/**
 * @brief bugreport_http_proc
 * @param a_http_simple
 * @param a_arg
 */
static void bugreport_http_proc(struct dap_http_simple *a_http_simple, void * a_arg)
{
    // data:text/html,<form action=http://192.168.100.92:8079/bugreport/ method=post><input name=a></form>
    log_it(L_DEBUG, "bugreport_http_proc request");
    http_status_code_t * return_code = (http_status_code_t*) a_arg;
    //if(dap_strcmp(cl_st->http->url_path, BUGREPORT_URL) == 0 )
    if(dap_strcmp(a_http_simple->http->action, "POST") == 0) {
        //a_http_simple->request_byte;
        //a_http_simple->request_size;
        //a_http_simple->http->in_content_length;

        if(!bugreport_write_to_file(a_http_simple->request_byte, a_http_simple->request_size)) {
            a_http_simple->reply = dap_strdup_printf("Bug Report saved successfully)");
        }
        else {
            a_http_simple->reply = dap_strdup_printf("Bug Report not saved(");
        }
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_OK;

    } else {
        log_it(L_ERROR, "Wrong action '%s' for the request. Must be 'POST'", a_http_simple->http->action);
        a_http_simple->reply = dap_strdup_printf("Wrong action '%s' for the request. Must be 'POST'",
                a_http_simple->http->action);
        a_http_simple->reply_size = strlen(a_http_simple->reply);
        *return_code = Http_Status_NotFound;
    }
}

/**
 * @brief dap_chain_net_bugreport_add_proc
 * @param sh HTTP server instance
 */
void dap_chain_net_bugreport_add_proc(struct dap_http * sh)
{
    const char * url = BUGREPORT_URL;
    dap_http_simple_proc_add(sh, url, 14096, bugreport_http_proc);
}

