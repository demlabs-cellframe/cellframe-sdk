/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include "utlist.h"

#include "dap_chain_net_srv.h"

#define LOG_TAG "chain_net_srv"

static size_t m_uid_count;
static dap_chain_net_srv_uid_t * m_uid;

/**
 * @brief dap_chain_net_srv_init
 * @return
 */
int dap_chain_net_srv_init()
{
    m_uid = NULL;
    m_uid_count = 0;

    return 0;
}

/**
 * @brief dap_chain_net_srv_deinit
 */
void dap_chain_net_srv_deinit()
{

}

/**
 * @brief dap_chain_net_srv_add
 * @param a_srv
 */
void dap_chain_net_srv_add(dap_chain_net_srv_t * a_srv)
{

}

/**
 * @brief dap_chain_net_srv_get
 * @param a_uid
 * @return
 */
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid)
{

}

/**
 * @brief dap_chain_net_srv_count
 * @return
 */
<<<<<<< HEAD
const size_t dap_chain_net_srv_count()
=======
 size_t dap_chain_net_srv_count(void)
>>>>>>> bugfix-12345
{

}

/**
 * @brief dap_chain_net_srv_list
 * @return
 */
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list()
{

}
