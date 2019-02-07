/*
 * Authors:
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

typedef struct dap_http_user_agent {
    char* name; // Ex: "DapVpnClient/2.2
    char* comment; // text after name
    unsigned short major_version;
    unsigned short minor_version;
} dap_http_user_agent_t;

dap_http_user_agent_t* dap_http_user_agent_new(const char* a_name,
                                               const char* a_comment,
                                               unsigned short a_major_version,
                                               unsigned short a_minor_version);

void dap_http_user_agent_delete(dap_http_user_agent_t* a_agent);

// If parsing not successful - returns NULL
dap_http_user_agent_t* dap_http_user_agent_new_from_str(const char* a_user_agent_str);

// Allocates memory for string and returns result
char* dap_http_user_agent_to_string(dap_http_user_agent_t* a_agent);

// returns:
// 0 - equals
// 1 - a_agent1 version above then a_agent2
// -1 - a_agent2 version above then a_agent1
int dap_http_user_agent_versions_compare(dap_http_user_agent_t* a_agent1,
                                         dap_http_user_agent_t* a_agent2);
#endif
