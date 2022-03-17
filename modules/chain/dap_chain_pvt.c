/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dap_chain_pvt.h"


#define LOG_TAG "dap_chain_pvt"


void dap_chain_add_mempool_notify_callback(dap_chain_t *a_chain, dap_global_db_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_chain_gdb_notifier_t *l_notifier = DAP_NEW(dap_chain_gdb_notifier_t);
    l_notifier->callback = a_callback;
    l_notifier->cb_arg = a_cb_arg;
    DAP_CHAIN_PVT(a_chain)->mempool_notifires = dap_list_append(DAP_CHAIN_PVT(a_chain)->mempool_notifires, l_notifier);
}




