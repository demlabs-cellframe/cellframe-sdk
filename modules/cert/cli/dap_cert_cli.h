/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Sources         https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of Cellframe SDK the open source project
 *
 *    Cellframe SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    Cellframe SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize certificate CLI commands
 * 
 * Registers certificate-related CLI commands with the CLI server.
 * Commands: cert list - displays all loaded certificates from ca_folders
 * 
 * @return 0 on success, negative error code on failure
 */
int dap_cert_cli_init(void);

/**
 * @brief Cleanup certificate CLI
 */
void dap_cert_cli_deinit(void);

#ifdef __cplusplus
}
#endif
