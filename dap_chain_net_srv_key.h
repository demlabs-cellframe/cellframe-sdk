/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * CellFrame       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2019
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

#pragma once

#include <stdint.h>
#include <stdbool.h>

// Parse a_service_key from service client
bool dap_chain_net_srv_key_parse(const char *a_service_key, char **a_addr_base58, char **a_sign_hash);
// Create new service_key
char* dap_chain_net_srv_key_create(const char *a_wallet_name);

// Create new key hash
char* dap_chain_net_srv_key_create_hash(const char *a_wallet_name, char **a_addr_base58);
// Checking service_key from service client
bool dap_chain_net_srv_key_check(char *a_addr_base58, const char *a_sign_hash_str);

