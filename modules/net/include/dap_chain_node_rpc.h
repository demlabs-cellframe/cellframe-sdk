/*
 * Authors:
 * Pavel Uhanov <pavel.uhanov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

 void dap_chain_node_rpc_init(dap_config_t *a_cfg);
 bool dap_chain_node_rpc_is_my_node_authorized();
 int dap_chain_node_rpc_info_save(dap_chain_node_info_t *a_node_info);
 dap_string_t *dap_chain_node_rpc_list();