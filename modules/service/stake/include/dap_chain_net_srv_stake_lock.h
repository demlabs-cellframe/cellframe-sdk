/*
 * Authors:
 * Davlet Sibgatullin <davlet.sibgatullin@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#pragma once

#define DAP_CHAIN_NET_SRV_STAKE_LOCK_ID 0x12

int dap_chain_net_srv_stake_lock_init(void);
void dap_chain_net_srv_stake_lock_deinit(void);

typedef enum s_com_stake_lock_err{
    DAP_CHAIN_NODE_CLI_COM_STAKE_LOCK_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_STAKE_LOCK_NOT_RECOGNIZED_ERR
}s_com_stake_lock_err_t;
