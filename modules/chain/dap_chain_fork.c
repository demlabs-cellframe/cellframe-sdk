/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Cellframe Network: https://cellframe.net
 * Copyright  (c) 2023
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <assert.h>
#include <uthash.h>

#include "dap_chain_common.h"
#include "dap_common.h"
#include "dap_chain_fork.h"

#define LOG_TAG "dap_chain_fork"

struct fork_hh
{
    dap_chain_net_id_t net_id;

    // Forks current and coming
    struct {
        dap_chain_fork_id_t id;
        dap_chain_fork_t * fork; // if NULL for coming that means nothing is coming next
    } current, coming, last;

    // UTHash handler
    UT_hash_handle hh;
} * s_forks = NULL;


/**
 * @brief dap_chain_fork_get_last
 * @param a_net_id
 * @return
 */
dap_chain_fork_t * dap_chain_fork_get_last(dap_chain_net_id_t a_net_id)
{
    struct fork_hh * l_hh_obj = NULL;
    HASH_FIND(hh, s_forks, &a_net_id, sizeof(a_net_id), l_hh_obj);
    return l_hh_obj ? l_hh_obj->last.fork : NULL;
}

/**
 * @brief dap_chain_fork_get_current
 * @return
 */
dap_chain_fork_t * dap_chain_fork_get_current(dap_chain_net_id_t a_net_id)
{
    struct fork_hh * l_hh_obj = NULL;
    HASH_FIND(hh, s_forks, &a_net_id, sizeof(a_net_id), l_hh_obj);
    return l_hh_obj ? l_hh_obj->current.fork : NULL;
}

/**
 * @brief dap_chain_fork_get_coming
 * @param a_net_id
 * @return
 */
dap_chain_fork_t * dap_chain_fork_get_coming(dap_chain_net_id_t a_net_id)
{
    struct fork_hh * l_hh_obj = NULL;
    HASH_FIND(hh, s_forks, &a_net_id, sizeof(a_net_id), l_hh_obj);
    return l_hh_obj ? l_hh_obj->coming.fork : NULL;
}

/**
 * @brief dap_chain_fork_check
 * @param a_chain_id
 * @param a_atom_number
 * @return
 */
bool dap_chain_fork_check(dap_chain_fork_t * a_fork, uint64_t a_atom_number,  dap_chain_id_t a_chain_id)
{
    if( a_fork){
        struct fork_hh * l_hh = (struct fork_hh *) a_fork->hh_obj;
        assert(l_hh);
        if ( a_fork->chain_id.raw == a_chain_id.raw && a_atom_number == a_fork->atom_number){
            log_it(L_MSG,"On chain 0x%"DAP_UINT64_FORMAT_X":0x%"DAP_UINT64_FORMAT_X" was detected atom #%"DAP_UINT64_FORMAT_U" wich means activation of new fork \"%s\"",
                   a_fork->net_id.uint64, a_fork->chain_id.uint64, a_atom_number, a_fork->name);

            l_hh->current = l_hh->coming;
            assert(l_hh->current.fork);

            if( l_hh->current.fork->callback )
                l_hh->current.fork->callback(l_hh->current.fork);

            return true;
        }
    }
    return false;
}

/**
 * @brief dap_chain_fork_add
 * @param a_net_id
 * @param a_id
 * @param a_name
 * @param a_atom_number
 * @param a_chain_id
 * @param a_callback
 * @return
 */
dap_chain_fork_t * dap_chain_fork_add(dap_chain_net_id_t a_net_id, const char * a_name, uint64_t a_atom_number, dap_chain_id_t a_chain_id, dap_chain_fork_callback_t a_callback)
{
    struct fork_hh * l_hh_obj = NULL;
    HASH_FIND(hh,s_forks, &a_net_id, sizeof(a_net_id), l_hh_obj);
    if (! l_hh_obj){
        l_hh_obj = DAP_NEW_Z(struct fork_hh);

    }
    dap_chain_fork_t * l_fork;
}
