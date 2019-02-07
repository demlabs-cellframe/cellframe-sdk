/*
 * Authors:
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/kelvinblockchain
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

#ifndef _DAP_HTTP_USER_AGENT_H_
#define _DAP_HTTP_USER_AGENT_H_

typedef struct dap_http_user_agent* dap_http_user_agent_ptr_t;

/**
 * @brief dap_http_user_agent_new
 * @param a_name
 * @param a_comment - Can be NULL
 * @param a_major_version
 * @param a_minor_version
 * @return
 */
dap_http_user_agent_ptr_t dap_http_user_agent_new(const char* a_name,
                                                  unsigned short a_major_version,
                                                  unsigned short a_minor_version,
                                                  const char* a_comment);

/**
 * @brief dap_http_user_agent_delete
 * @param a_agent
 */
void dap_http_user_agent_delete(dap_http_user_agent_ptr_t a_agent);

/**
 * @brief dap_http_user_agent_new_from_str
 * @param a_user_agent_str
 * @return If parsing not successful - NULL
 */
dap_http_user_agent_ptr_t dap_http_user_agent_new_from_str(const char* a_user_agent_str);


/**
 * @brief dap_http_user_agent_to_string
 * @param a_agent
 * @details Don't allocates memory. Uses internal buffer
 * @return
 */
char* dap_http_user_agent_to_string(dap_http_user_agent_ptr_t a_agent);

/**
 * @brief dap_http_user_agent_versions_compare
 * @param a_agent1
 * @param a_agent2
 * @return 0 == equals -1 == a_agent1 < a_agent2 | 1 == a_agent1 > a_agent2 | -2 == Erorr agent names not equals
 */
int dap_http_user_agent_versions_compare(dap_http_user_agent_ptr_t a_agent1,
                                         dap_http_user_agent_ptr_t a_agent2);

unsigned int dap_http_user_agent_get_major_version(dap_http_user_agent_ptr_t);
unsigned int dap_http_user_agent_get_minor_version(dap_http_user_agent_ptr_t);
const char* dap_http_user_agent_get_name(dap_http_user_agent_ptr_t);
const char* dap_http_user_agent_get_comment(dap_http_user_agent_ptr_t);
#endif
