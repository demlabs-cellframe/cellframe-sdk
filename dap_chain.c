/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

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


#include "dap_chain.h"

#define LOG_TAG "dap_chain"

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init()
{
    log_it(L_INFO,"DapChain module init");
}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit()
{
    log_it(L_INFO,"DapChain module deinit");

}


/**
 * @brief dap_chain_open
 * @param a_file_name
 * @return
 */
dap_chain_t * dap_chain_open(const char * a_file_name)
{

}

/**
 * @brief dap_chain_remap
 * @param a_chain
 * @param a_offset
 */
void dap_chain_remap(dap_chain_t * a_chain, size_t a_offset)
{

}

/**
 * @brief dap_chain_save
 * @param a_chain
 */
void dap_chain_save(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_close
 * @param a_chain
 */
void dap_chain_close(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_info_dump_log
 * @param a_chain
 */
void dap_chain_info_dump_log(dap_chain_t * a_chain)
{

}
