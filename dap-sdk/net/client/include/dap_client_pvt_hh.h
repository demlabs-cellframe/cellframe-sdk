/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020
 *
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

#include <stdio.h>
#include <pthread.h>
#include <uthash.h>

#include "dap_common.h"
#include "dap_client_pvt.h"

//#include <stdio.h>
//#include <pthread.h>
//#include <uthash.h>

//#include "dap_common.h"
//#include "dap_client_pvt.h"

typedef struct dap_client_pvt_hh {
    dap_client_pvt_t *client_pvt;
    UT_hash_handle hh;
} dap_client_pvt_hh_t;

#ifdef __cplusplus
extern "C" {
#endif

// List of active connections
static dap_client_pvt_hh_t *s_client_pvt_list = NULL;
// for separate access to s_conn_list
static pthread_mutex_t s_client_pvt_list_mutex = PTHREAD_MUTEX_INITIALIZER;

int dap_client_pvt_hh_lock(void);
int dap_client_pvt_hh_unlock(void);
void* dap_client_pvt_hh_get(dap_client_pvt_t* a_client_pvt);
bool dap_client_pvt_check(dap_client_pvt_t* a_client_pvt);
int dap_client_pvt_hh_add(dap_client_pvt_t* a_client_pvt);
int dap_client_pvt_hh_del(dap_client_pvt_t *a_client_pvt);

#ifdef __cplusplus
}
#endif
